from pocha import describe, it, before, beforeEach, afterEach
from hamcrest import *
from unittest.mock import patch
import scrypt
from base64 import b64encode
import re
import yaml

from server import app as server_app, limiter
import util
import db

def authHeader(username, password):
	return {
		'Authorization': 'Basic ' + b64encode(
			bytes(username + ':' + password, 'utf-8')
		).decode('utf-8')
	}

def assertResponse(response, code, text, desc=None):
	assert_that(response.status_code, equal_to(code), desc)
	assert_that(response.get_data(as_text=True), equal_to(text), desc)

# TODO Pocha doesn't currently support applying afterEach to nested
# describe blocks, so we need this as a work-around for now.
def cleanupUsers(name):
	assert_that(name, not_none())
	with server_app.app_context():
		db.getDb().execute('DELETE FROM Users WHERE name = ?', [name])
		db.getDb().commit()

def cleanupCodes(code):
	assert_that(code, not_none())
	with server_app.app_context():
		db.getDb().execute('DELETE FROM Codes WHERE code = ?', [code])
		db.getDb().commit()

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
	salt = 'saltything'
	test_user = {
		'name': test_name,
		'pass_salt': salt,
		'pass_hash': scrypt.hash(test_pass, salt)
	}

	test_id = None

	# This is kind of awful but it works!
	def getLoginCSRFToken():
		login = app.get('/login')
		token = re.search(b'name="csrf_token" value="(.*)"', login.data)
		return token.group(1).decode('utf-8')

	def enableRateLimiter(is_enabled):
		limiter.reset()
		limiter.enabled = is_enabled

	def removeLoginToken():
		with app.session_transaction() as session:
			session.pop('login', None)

	@before
	def _beforeAll():
		cleanupUsers(test_name)
		cleanupCodes(test_code)
		enableRateLimiter(False)

	@describe('Login form')
	def loginForm():

		@beforeEach
		def _beforeEach():
			with server_app.app_context():
				db.addUser(test_user)
			enableRateLimiter(False)

		@afterEach
		def _afterEach():
			cleanupUsers(test_name)
			removeLoginToken()

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
			with app.session_transaction() as session:
				assert_that(session.get('login', None), is_(none()))
			response = app.post('/login/form', data={
				'csrf_token': getLoginCSRFToken(),
				'username': test_name,
				'password': test_pass
			})
			assertResponse(response, 200, 'Ok')
			with app.session_transaction() as session:
				assert_that(session.get('login', None), is_not(none()))

		@it('Missing CSRF token')
		def missingCSRFToken():
			response = app.post('/login/form', data={
				'username': test_name,
				'password': test_pass
			})
			assertResponse(response, 400, 'Session expired. Reload and try again')

		@it('Empty and invalid body')
		def emptyBody():
			data = { 'csrf_token': getLoginCSRFToken() }
			res1 = app.post('/login/form')
			res2 = app.post('/login/form', data={})
			res3 = app.post('/login/form', data=data)
			res4 = app.post('/login/form', data='I am not json')
			res5 = app.post('/login/form', json={})
			res6 = app.post('/login/form', json=data)
			assertResponse(res1, 400, 'Session expired. Reload and try again')
			assertResponse(res2, 400, 'Session expired. Reload and try again')
			assertResponse(res3, 400, 'Missing username / password in form body')
			assertResponse(res4, 400, 'Session expired. Reload and try again')
			assertResponse(res5, 400, 'Session expired. Reload and try again')
			assertResponse(res6, 400, 'Session expired. Reload and try again')

		@it('Hitting rate limit')
		def rateLimit():
			enableRateLimiter(True)
			data = {
				'csrf_token': getLoginCSRFToken(),
				'username': test_name,
				'password': 'bad pass'
			}
			for i in range(rate_login):
				res = app.post('/login/form', data=data)
				assertResponse(res, 403, 'Forbidden',
					'Prematurely hit limit at %d/%d requests' % (i + 1, rate_login)
				)
			res = app.post('/login/form', data=data)
			assertResponse(res, 429, 'Too many requests')

		@it('Already have a login cookie')
		def alreadyHaveLogin():
			with app.session_transaction() as session:
				session['login'] = 'test token'
			res = app.post('/login/form', data={
				'csrf_token': getLoginCSRFToken(),
				'username': test_name,
				'password': test_pass
			})
			assertResponse(res, 400, 'Already logged in')

	@describe('Login basic auth')
	def loginBasic():

		@beforeEach
		def _beforeEach():
			with server_app.app_context():
				db.addUser(test_user)
			enableRateLimiter(False)

		@afterEach
		def _afterEach():
			cleanupUsers(test_name)

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
			headers = authHeader(test_name, 'bad pass')
			for i in range(rate_login):
				res = app.post('/login/basic', headers=headers)
				assertResponse(res, 403, 'Forbidden',
					'Prematurely hit limit at %d/%d requests' % (i + 1, rate_login)
				)
			res = app.post('/login/basic', headers=headers)
			assertResponse(res, 429, 'Too many requests')

	@describe('Login json')
	def loginJson():

		@beforeEach
		def _beforeEach():
			with server_app.app_context():
				db.addUser(test_user)
			enableRateLimiter(False)

		@afterEach
		def _afterEach():
			cleanupUsers(test_name)
			removeLoginToken()

		@it('Successful login')
		def goodLogin():
			with app.session_transaction() as session:
				assert_that(session.get('login', None), is_(none()))
			response = app.post('/login/json',
				headers={ 'X-CSRFToken': getLoginCSRFToken() },
				json={
					'username': test_name,
					'password': test_pass
				}
			)
			assertResponse(response, 200, 'Ok')
			with app.session_transaction() as session:
				assert_that(session.get('login', None), is_not(none()))

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

		@it('Empty and invalid body')
		def emptyBody():
			headers = { 'X-CSRFToken': getLoginCSRFToken() }
			res1 = app.post('/login/json', headers=headers)
			res2 = app.post('/login/json', headers=headers, data={})
			res3 = app.post('/login/json', headers=headers, data=None)
			res4 = app.post('/login/json', headers=headers, json={})
			res5 = app.post('/login/json', headers=headers, json=None)
			res6 = app.post('/login/json', headers=headers, json='I am not json')
			res7 = app.post('/login/json', headers=headers, json=1234)
			assertResponse(res1, 400, 'Missing JSON body')
			assertResponse(res2, 400, 'Missing JSON body')
			assertResponse(res3, 400, 'Missing JSON body')
			assertResponse(res4, 400, 'Missing username / password in JSON body')
			assertResponse(res5, 400, 'Missing JSON body')
			assertResponse(res6, 400, 'Malformed JSON body')
			assertResponse(res7, 400, 'Malformed JSON body')

		@it('Hitting rate limit')
		def rateLimit():
			enableRateLimiter(True)
			headers = { 'X-CSRFToken': getLoginCSRFToken() }
			json = {
				'username': test_name,
				'password': 'bad pass'
			}
			for i in range(rate_login):
				res = app.post('/login/json', headers=headers, json=json)
				assertResponse(res, 403, 'Forbidden',
					'Prematurely hit limit at %d/%d requests' % (i + 1, rate_login)
				)
			res = app.post('/login/json', headers=headers, json=json)
			assertResponse(res, 429, 'Too many requests')

		@it('Already have a login cookie')
		def alreadyHaveLogin():
			with app.session_transaction() as session:
				session['login'] = 'test token'

			headers = { 'X-CSRFToken': getLoginCSRFToken() }
			json = {
				'username': test_name,
				'password': test_pass
			}
			res = app.post('/login/json', headers=headers, json=json)
			assertResponse(res, 400, 'Already logged in')

	@describe('Add Email')
	def addEmail():

		@beforeEach
		def _beforeEach():
			nonlocal test_id
			with server_app.app_context():
				test_id = db.addUser(test_user)

		@afterEach
		def _afterEach():
			cleanupUsers(test_name)

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
			with server_app.app_context():
				assert_that(db.getCode(code), not_none())

			cleanupCodes(code)

	@describe('Confirm Code')
	def confirmCode():

		@beforeEach
		def _beforeEach():
			nonlocal test_id
			with server_app.app_context():
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
			with server_app.app_context():
				db.useCode(test_code)
				response = app.get('/update/email/confirm/' + test_code)
				assertResponse(response, 403, 'Forbidden')

				user = db.getUserById(test_id)
				assert_that(user.get('email', None), none())

		@it('Attempting to confirm code for a deleted user')
		def confirmCodeDeletedUser():
			nonlocal test_id
			with server_app.app_context():
				db.getDb().execute('DELETE FROM Users WHERE id = ?', [test_id])
				db.getDb().commit()

				response = app.get('/update/email/confirm/' + test_code)
				assertResponse(response, 403, 'Forbidden')
				assert_that(db.getUserById(test_id), none())

		@it('Successfully confirm email via code')
		def emailAdded():
			nonlocal test_id
			response = app.get('/update/email/confirm/' + test_code)
			assertResponse(response, 200, 'Ok')

			with server_app.app_context():
				user = db.getUserById(test_id)
				assert_that(user.get('email'), equal_to(test_email))
				assert_that(db.getCode(test_code), none())

	@describe('Generic Error')
	def genericError():

		@it('Bad Endpoint')
		def badEndpoint():
			response = app.get('/bad/endpoint')
			assertResponse(response, 403, 'Forbidden')

