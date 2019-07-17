from pocha import describe, it, before, beforeEach, afterEach
from hamcrest import *
from unittest.mock import patch
import scrypt
from base64 import b64encode
import re
import yaml
from peewee import fn

from server import app as server_app, makeUniqueCode, limiter
from db import User, Code

def authHeader(username, password):
	return {
		'Authorization': 'Basic ' + b64encode(
			bytes(username + ':' + password, 'utf-8')
		).decode('utf-8')
	}

def assertResponse(response, code, text, desc=None):
	assert_that(response.status_code, equal_to(code), desc)
	assert_that(response.get_data(as_text=True), equal_to(text), desc)

@describe('Server Tests')
def serverTests():

	config = yaml.safe_load(open('config.yaml'))
	rate_login = int(re.search('(\d+)', config['rate_login']).group(1))

	server_app.config['TESTING'] = True
	app = server_app.test_client()
	test_name = 'ServerTest'
	test_pass = 'testpass'
	test_code = 'Test1234'
	test_email = 'test@email.com'
	test_salt = 'saltything'
	test_hash = scrypt.hash(test_pass, test_salt)

	test_user = None

	# This is kind of awful but it works!
	def getLoginCSRFToken():
		login = app.get('/login')
		token = re.search(b'name="csrf_token" value="(.*)"', login.data)
		return token.group(1).decode('utf-8')

	# TODO can we move this?
	def enableRateLimiter(is_enabled):
		limiter.reset()
		limiter.enabled = is_enabled

	# TODO Pocha doesn't currently support applying afterEach to nested
	# describe blocks, so we need this as a work-around for now.
	def createTestUser():
		nonlocal test_user
		test_user = User.create(
			name      = test_name,
			pass_hash = test_hash,
			pass_salt = test_salt,
			email     = test_email
		)
		return test_user

	def cleanupUsers():
		nonlocal test_user
		if test_user is not None:
			test_user.delete_instance()

	def cleanupCodes(code):
		assert_that(code, not_none())
		Code.delete().where(Code.code == code).execute()


	@before
	def _beforeAll():
		cleanupUsers()
		cleanupCodes(test_code)
		enableRateLimiter(False)

	@describe('Login form')
	def loginForm():

		@beforeEach
		def _beforeEach():
			createTestUser()
			enableRateLimiter(False)

		@afterEach
		def _afterEach():
			cleanupUsers()

		@it('User does not exist')
		def noUser():
			response = app.post('/login/form', data={
				'csrf_token': getLoginCSRFToken(),
				'username': 'Idontexist',
				'password': 'lalala'
			})
			assertResponse(response, 403, 'Forbidden')

		@it('Existing user but bad password')
		def badPassword():
			response = app.post('/login/form', data={
				'csrf_token': getLoginCSRFToken(),
				'username': test_name,
				'password': 'badpassword'
			})
			assertResponse(response, 403, 'Forbidden')

		@it('Successful login')
		def goodLogin():
			response = app.post('/login/form', data={
				'csrf_token': getLoginCSRFToken(),
				'username': test_name,
				'password': test_pass
			})
			assertResponse(response, 200, 'Ok')

		@it('Missing CSRF token')
		def missingCSRFToken():
			response = app.post('/login/form', data={
				'username': test_name,
				'password': test_pass
			})
			assertResponse(response, 400, 'Session expired. Reload and try again')

		@it('Empty body')
		def emptyBody():
			res1 = app.post('/login/form')
			res2 = app.post('/login/form', data={})
			res3 = app.post('/login/form', json={})
			assertResponse(res1, 400, 'Session expired. Reload and try again')
			assertResponse(res2, 400, 'Session expired. Reload and try again')
			assertResponse(res3, 400, 'Session expired. Reload and try again')

		@it('Non-json body')
		def incorrectData():
			res = app.post('/login/form', data='I am not json')
			assertResponse(res, 400, 'Session expired. Reload and try again')

		@it('Hitting rate limit')
		def rateLimit():
			enableRateLimiter(True)
			data = {
				'csrf_token': getLoginCSRFToken(),
				'username': test_name,
				'password': test_pass
			}
			for i in range(rate_login):
				res = app.post('/login/form', data=data)
				assertResponse(res, 200, 'Ok',
					'Prematurely hit limit at %d/%d requests' % (i + 1, rate_login)
				)
			res = app.post('/login/form', data=data)
			assertResponse(res, 429, 'Too many requests')

	@describe('Login basic auth')
	def loginBasic():

		@beforeEach
		def _beforeEach():
			createTestUser()
			enableRateLimiter(False)

		@afterEach
		def _afterEach():
			cleanupUsers()

		@it('Successful login')
		def goodLogin():
			headers = authHeader(test_name, test_pass)
			response = app.post('/login/basic', headers=headers)
			assertResponse(response, 200, 'Ok')

		@it('User does not exist')
		def userDoesNotExist():
			headers = authHeader('baduser', 'pass')
			response = app.post('/login/basic', headers=headers)
			assertResponse(response, 403, 'Forbidden')

		@it('Password does not match')
		def passDoesNotMatch():
			headers = authHeader(test_name, 'badpass')
			response = app.post('/login/basic', headers=headers)
			assertResponse(response, 403, 'Forbidden')

		@it('Empty auth')
		def emptyBody():
			res1 = app.post('/login/form')
			res2 = app.post('/login/form', headers={})
			assertResponse(res1, 400, 'Session expired. Reload and try again')
			assertResponse(res2, 400, 'Session expired. Reload and try again')

		@it('Hitting rate limit')
		def rateLimit():
			enableRateLimiter(True)
			headers = authHeader(test_name, test_pass)
			for i in range(rate_login):
				res = app.post('/login/basic', headers=headers)
				assertResponse(res, 200, 'Ok',
					'Prematurely hit limit at %d/%d requests' % (i + 1, rate_login)
				)
			res = app.post('/login/basic', headers=headers)
			assertResponse(res, 429, 'Too many requests')

	@describe('Login json')
	def loginJson():

		@beforeEach
		def _beforeEach():
			createTestUser()
			enableRateLimiter(False)

		@afterEach
		def _afterEach():
			cleanupUsers()

		@it('Successful login')
		def goodLogin():
			response = app.post('/login/json',
				headers={ 'X-CSRFToken': getLoginCSRFToken() },
				json={
					'username': test_name,
					'password': test_pass
				}
			)
			assertResponse(response, 200, 'Ok')

		@it('User does not exist')
		def userDoesNotExist():
			response = app.post('/login/json',
				headers={ 'X-CSRFToken': getLoginCSRFToken() },
				json={
					'username': 'baduser',
					'password': 'whatever man'
				}
			)
			assertResponse(response, 403, 'Forbidden')

		@it('Password does not match')
		def passDoesNotMatch():
			response = app.post('/login/json',
				headers={ 'X-CSRFToken': getLoginCSRFToken() },
				json={
					'username': test_name,
					'password': 'bad password'
				}
			)
			assertResponse(response, 403, 'Forbidden')

		@it('Missing CSRF token')
		def missingCSRFToken():
			response = app.post('/login/json', json={
				'username': test_name,
				'password': test_pass
			})
			assertResponse(response, 400, 'Session expired. Reload and try again')

		@it('Empty body')
		def emptyBody():
			headers = { 'X-CSRFToken': getLoginCSRFToken() }
			res1 = app.post('/login/form', headers=headers)
			res2 = app.post('/login/form', headers=headers, data={})
			res3 = app.post('/login/form', headers=headers, json={})
			assertResponse(res1, 403, 'Forbidden')
			assertResponse(res2, 403, 'Forbidden')
			assertResponse(res3, 403, 'Forbidden')

		@it('Non-json body')
		def incorrectData():
			headers = { 'X-CSRFToken': getLoginCSRFToken() }
			res = app.post('/login/form', headers=headers, data='I am not json')
			assertResponse(res, 403, 'Forbidden')

		@it('Hitting rate limit')
		def rateLimit():
			enableRateLimiter(True)
			headers = { 'X-CSRFToken': getLoginCSRFToken() }
			json = {
				'username': test_name,
				'password': test_pass
			}
			for i in range(rate_login):
				res = app.post('/login/json', headers=headers, json=json)
				assertResponse(res, 200, 'Ok',
					'Prematurely hit limit at %d/%d requests' % (i + 1, rate_login)
				)
			res = app.post('/login/json', headers=headers, json=json)
			assertResponse(res, 429, 'Too many requests')

	@describe('Add Email')
	def addEmail():

		@beforeEach
		def _beforeEach():
			createTestUser()

		@afterEach
		def _afterEach():
			cleanupUsers()

		@it('User does not exist')
		def userDoesNotExist():
			response = app.put('/update/email',
				headers=authHeader('baduser', 'pass'),
				data='example@email.com'
			)
			assertResponse(response, 403, 'Forbidden')

		@it('Password does not match')
		def passDoesNotMatch():
			response = app.put('/update/email',
				headers=authHeader(test_name, 'badpass'),
				data='example@email.com'
			)
			assertResponse(response, 403, 'Forbidden')

		@it('Invalid email')
		def emailInvalid():
			response = app.put('/update/email',
				headers=authHeader(test_name, test_pass),
				data='bademail'
			)
			assertResponse(response, 400, 'Invalid email')

		@it('Code added')
		@patch('server.sendmail')
		def codeAdded(mock_emailer):
			email = 'new@email.com'
			response = app.put('/update/email',
				headers=authHeader(test_name, test_pass),
				data=email
			)
			assertResponse(response, 200, 'Ok')

			args = mock_emailer.call_args[0]
			assert_that(args[0], equal_to(email))
			assert_that(args[1], equal_to('Funbox Email Verification'))

			# Check that our confirm link contains a valid code
			match = re.search(r'email\/confirm\/(\w{8})', args[2])
			assert_that(match, not_none())
			code = match.groups()[0]
			assert_that(Code.get_by_code(code), not_none())

			cleanupCodes(code)

		@it('Ensures unique codes')
		def codesUnique():
			nonlocal test_user

			# Add a bunch of codes
			num_codes = 10
			added_codes = []
			for _ in range(num_codes):
				code = makeUniqueCode()
				Code.create_email(code=code, user=test_user, email='test@email.com')
				added_codes.append(code)

			# Verify that all codes were added and unique
			codes_added = Code                      \
				.select(fn.COUNT(4).alias('count')) \
				.distinct()                         \
				.where(Code.code in added_codes)    \
				.get()                              \
				.count
			assert_that(codes_added, equal_to(num_codes))

			# Cleanup
			Code.delete().where(Code.code in added_codes).execute()

	@describe('Confirm Code')
	def confirmCode():

		@beforeEach
		def _beforeEach():
			nonlocal test_user
			createTestUser()
			Code.create_email(code=test_code, user=test_user, email=test_email)

		@afterEach
		def _afterEach():
			cleanupCodes(test_code)
			cleanupUsers()

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
			nonlocal test_user
			test_user.email = None
			test_user.save()

			Code.use_code(test_code)
			response = app.get('/update/email/confirm/' + test_code)
			assertResponse(response, 403, 'Forbidden')

			user = User.get_by_id(test_user.id)
			assert_that(user.email, is_(none()))

		# Can't actually delete a user with codes without getting a
		# ForeignKey constraint exception from SQLite.
		# TODO maybe we don't need this test (or make some other test)?
		#@it('Attempting to confirm code for a deleted user')
		#def confirmCodeDeletedUser():
		#	nonlocal test_user
		#	cleanupUsers()
		#	response = app.get('/update/email/confirm/' + test_code)
		#	assertResponse(response, 403, 'Forbidden')
		#	assert_that(User.get_by_name(test_name), is_(none()))

		@it('Successfully confirm email via code')
		def emailAdded():
			nonlocal test_user
			response = app.get('/update/email/confirm/' + test_code)
			assertResponse(response, 200, 'Ok')

			user = User.get_by_id(test_user.id)
			assert_that(user.email, equal_to(test_email))
			assert_that(Code.get_by_code(test_code), is_(none()))

	@describe('Generic Error')
	def genericError():

		@it('Bad Endpoint')
		def badEndpoint():
			response = app.get('/bad/endpoint')
			assertResponse(response, 403, 'Forbidden')

