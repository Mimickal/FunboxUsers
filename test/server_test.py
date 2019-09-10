from base64 import b64encode
import json
import re
from unittest.mock import patch

from hamcrest import *
from peewee import fn
from pocha import afterEach, before, beforeEach, describe, it

from db import User, Code, PendingEmail, LoginCode
from server import app as server_app, limiter
import testutil
import util


def authHeader(username, password):
	return {
		'Authorization': 'Basic ' + b64encode(
			bytes(username + ':' + password, 'utf-8')
		).decode('utf-8')
	}

def assertResponse(response, code, text, desc=None):
	assert_that(response.status_code, equal_to(code), desc)
	assert_that(response.get_data(as_text=True), equal_to(text), desc)

def assertRedirect(response, url):
	assert_that(response.status_code, equal_to(302))
	got_url = re.search('href="([.\/\w]+)"', response.get_data(as_text=True)).group(1)
	assert_that(got_url, equal_to(url))

def getJsonFrom(response):
	return json.loads(response.get_data(as_text=True))

@describe('Server Tests')
def serverTests():

	config = util.loadYaml('config.yaml')
	rate_login = int(re.search('(\d+)', config['rate_login']).group(1))

	server_app.config['TESTING'] = True
	app = server_app.test_client()
	test_name = 'ServerTest'
	test_pass = 'testpass'
	test_code = 'Test1234'
	test_email = 'test@email.com'
	test_salt = 'saltything'
	test_hash = util.hashPassword(test_pass, test_salt)

	test_user = None

	# This is kind of awful but it works!
	def getLoginCSRFToken():
		login = app.get('/login')
		token = re.search(b'name="csrf_token" value="(.*)"', login.data)
		return token.group(1).decode('utf-8')

	def getLoginSession():
		# Sets the session for the test app
		response = app.post('/login/form', data={
			'csrf_token': getLoginCSRFToken(),
			'username': test_name,
			'password': test_pass
		})
		assertRedirect(response, '/account')

	# TODO can we move this?
	def enableRateLimiter(is_enabled):
		limiter.reset()
		limiter.enabled = is_enabled

	def removeLoginToken():
		with app.session_transaction() as session:
			session.pop('login', None)

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

	@before
	def _beforeAll():
		testutil.clearDatabase()
		enableRateLimiter(False)

	@describe('Login page')
	def loginPage():

		@beforeEach
		def _beforeEach():
			with app.session_transaction() as session:
				session.clear()
			testutil.clearDatabase()
			createTestUser()

		@it('Redirects to account page when already logged in')
		def redirectToAccount():
			getLoginSession()
			response = app.get('/login')
			assertRedirect(response, '/account')

		#NOTE getting page HTML when not logged in is covered by getLoginSession

	@describe('Login form')
	def loginForm():

		@beforeEach
		def _beforeEach():
			with app.session_transaction() as session:
				session.clear()
			testutil.clearDatabase()
			createTestUser()
			enableRateLimiter(False)

		@afterEach
		def _afterEach():
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
				assert_that(session.get('login', None), none())
			response = app.post('/login/form', data={
				'csrf_token': getLoginCSRFToken(),
				'username': test_name,
				'password': test_pass
			})
			assertRedirect(response, '/account')
			with app.session_transaction() as session:
				code = session.get('login', None)
				assert_that(code, not_none())
			assert_that(Code.get_by_code(code), not_none())
			login_code = LoginCode.get_by_code(code)
			assert_that(login_code, not_none())
			assert_that(login_code.code, equal_to(code))

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

		@it('Clearing client cookie while logged in')
		def clearCookieWhenLoggedIn():
			getLoginSession()
			with app.session_transaction() as session:
				assert_that(session.get('login'), not_none())
				old_code = session.pop('login')

			res = app.post('/login/form', data={
				'csrf_token': getLoginCSRFToken(),
				'username': test_name,
				'password': test_pass,
			})
			assertRedirect(res, '/account')

			with app.session_transaction() as session:
				assert_that(session.get('login'), not_(equal_to(old_code)))

	@describe('Login basic auth')
	def loginBasic():

		@beforeEach
		def _beforeEach():
			testutil.clearDatabase()
			createTestUser()
			enableRateLimiter(False)

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
			testutil.clearDatabase()
			createTestUser()
			enableRateLimiter(False)

		@afterEach
		def _afterEach():
			removeLoginToken()

		@it('Successful login')
		def goodLogin():
			with app.session_transaction() as session:
				assert_that(session.get('login', None), none())
			response = app.post('/login/json',
				headers={ 'X-CSRFToken': getLoginCSRFToken() },
				json={
					'username': test_name,
					'password': test_pass
				}
			)
			assertRedirect(response, '/account')
			with app.session_transaction() as session:
				code = session.get('login', None)
				assert_that(code, not_none())
			assert_that(Code.get_by_code(code), not_none())
			login_code = LoginCode.get_by_code(code)
			assert_that(login_code, not_none())
			assert_that(login_code.code, equal_to(code))

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

		@it('Clearing client cookie while logged in')
		def clearCookieWhenLoggedIn():
			getLoginSession()
			with app.session_transaction() as session:
				assert_that(session.get('login'), not_none())
				old_code = session.pop('login')

			headers = { 'X-CSRFToken': getLoginCSRFToken() }
			json = {
				'username': test_name,
				'password': test_pass
			}
			res = app.post('/login/json', headers=headers, json=json)
			assertRedirect(res, '/account')

			with app.session_transaction() as session:
				assert_that(session.get('login'), not_(equal_to(old_code)))

	@describe('Log out user')
	def logoutUser():

		csrf_header = None

		@beforeEach
		def _beforeEach():
			nonlocal csrf_header
			with app.session_transaction() as session:
				session.clear()
			testutil.clearDatabase()
			createTestUser()
			csrf_header = { 'X-CSRFToken': getLoginCSRFToken() }

		@it('Invalid session')
		def invalidSession():
			response = app.post('/logout', headers=csrf_header)
			assertResponse(response, 403, 'Forbidden')

		@it('Invalid login code')
		def invalidLoginCode():
			getLoginSession()
			with app.session_transaction() as session:
				session['login'] = 'badtoken'
			response = app.post('/logout', headers=csrf_header)
			assertResponse(response, 403, 'Forbidden')

		@it('Missing CSRF token')
		def missingCSRFToken():
			getLoginSession()
			response = app.post('/logout')
			assertResponse(response, 400, 'Session expired. Reload and try again')

		@it('Successful logout')
		def successfulLogout():
			# Create and verify login state
			getLoginSession()
			with app.session_transaction() as session:
				code = session['login']
			login_code = LoginCode.get_by_user(test_user)
			assert_that(login_code, not_none())
			assert_that(login_code.code, equal_to(code))
			assert_that(Code.get_by_code(code).used_at, none())

			# Do logout
			response = app.post('/logout', headers=csrf_header)
			assertRedirect(response, '/login')

			# Verify session information has been destroyed
			with app.session_transaction() as session:
				assert_that(session.get('login', None), none())
			assert_that(LoginCode.get_by_user(test_user), none())
			assert_that(Code.get_by_code(code, include_used=True).used_at, not_none())

	@describe('Account page')
	def accountPage():

		@beforeEach
		def _beforeEach():
			with app.session_transaction() as session:
				session.clear()
			testutil.clearDatabase()
			createTestUser()

		@it('Get account page when logged in')
		def getAccountHTML():
			getLoginSession()
			response = app.get('/account')
			assert_that(response.status_code, equal_to(200))
			assert_that(
				response.get_data(as_text=True),
				contains_string('<title>Funbox Account Overview</title>')
			)

		@it('Redirected to login page when not logged in')
		def redirectToLogin():
			response = app.get('/account')
			assertRedirect(response, '/login')

	@describe('Fetch logged in user')
	def getAccountInfo():

		@beforeEach
		def _beforeEach():
			with app.session_transaction() as session:
				session.clear()
			testutil.clearDatabase()
			createTestUser()

		@it('Invalid session')
		def invalidSession():
			response = app.get('/user')
			assertResponse(response, 403, 'Forbidden')

		@it('Invalid login code')
		def invalidLoginCode():
			getLoginSession()
			with app.session_transaction() as session:
				session['login'] = 'badtoken'
			response = app.get('/user')
			assertResponse(response, 403, 'Forbidden')

		@it('Gets the logged in user')
		def getLoggedInUser():
			getLoginSession()
			response = app.get('/user')

			assert_that(response.status_code, equal_to(200))
			data = getJsonFrom(response)
			assert_that(data, has_entries({
				'name': test_user.name,
				'email': test_user.email
			}))
			assert_that(data, has_key('created_at'))
			assert_that(data, has_key('updated_at'))
			assert_that(data, has_key('accessed_at'))

		@it('Password is redacted')
		def getUserNoPassword():
			getLoginSession()
			response = app.get('/user')

			assert_that(response.status_code, equal_to(200))
			data = getJsonFrom(response)
			assert_that(data, not_(has_key('pass_hash')))
			assert_that(data, not_(has_key('pass_salt')))

		@it('Fetches pending email')
		def getUserPendingEmail():
			nonlocal test_user
			new_email = 'myfancy@new.email'
			new_code = Code.create(code=test_code)
			PendingEmail.create(
				user  = test_user,
				code  = new_code,
				email = new_email
			)

			getLoginSession()
			response = app.get('/user')

			assert_that(response.status_code, equal_to(200))
			data = getJsonFrom(response)
			assert_that(data, has_entries({
				'name': test_user.name,
				'email': test_user.email,
				'email_pending': new_email
			}))

		#@it('accessed_at is near now')
		# TODO this^ when accessed_at is implemented.
		# Probably check that accessed_at != created and updated

	@describe('Change password')
	def changePassword():

		csrf_header = None
		new_pass = 'mynewpassword'

		@beforeEach
		def _beforeEach():
			nonlocal csrf_header
			with app.session_transaction() as session:
				session.clear()
			testutil.clearDatabase()
			createTestUser()
			csrf_header = { 'X-CSRFToken': getLoginCSRFToken() }

		@it('Invalid session')
		@patch('util.sendEmail')
		def invalidSession(_):
			response = app.put('/update/password', headers=csrf_header)
			assertResponse(response, 403, 'Forbidden')

		@it('Invalid login code')
		@patch('util.sendEmail')
		def invalidLoginCode(_):
			getLoginSession()
			with app.session_transaction() as session:
				session['login'] = 'badtoken'
			response = app.put('/update/password', headers=csrf_header)
			assertResponse(response, 403, 'Forbidden')

		@it('Missing CSRF token')
		def missingCSRF():
			getLoginSession()
			response = app.put('/update/password')
			assertResponse(response, 400, 'Session expired. Reload and try again')

		@it('Missing required fields')
		@patch('util.sendEmail')
		def missingRequiredFields(_):
			getLoginSession()
			res = app.put('/update/password', headers=csrf_header, json={
				'pass_new': new_pass,
				'pass_new_conf': new_pass
			})
			assertResponse(res, 400, 'Missing fields')

			res = app.put('/update/password', headers=csrf_header, json={
				'pass_old': test_pass,
				'pass_new_conf': new_pass
			})
			assertResponse(res, 400, 'Missing fields')

			res = app.put('/update/password', headers=csrf_header, json={
				'pass_old': test_pass,
				'pass_new': new_pass
			})
			assertResponse(res, 400, 'Missing fields')

		@it('Missing data entirely')
		@patch('util.sendEmail')
		def missingDataEntirely(_):
			getLoginSession()
			response = app.put('/update/password', headers=csrf_header, data={})
			assertResponse(response, 400, 'Missing json data')

		@it('Old password incorrect')
		@patch('util.sendEmail')
		def oldPasswordIncorrect(_):
			getLoginSession()
			response = app.put('/update/password', headers=csrf_header, json={
				'pass_old': 'definitely wrong',
				'pass_new': new_pass,
				'pass_new_conf': new_pass
			})
			assertResponse(response, 400, 'Old password incorrect')

		@it('New password and confirmation do not match')
		@patch('util.sendEmail')
		def newPassConfDoesntMatch(_):
			getLoginSession()
			response = app.put('/update/password', headers=csrf_header, json={
				'pass_old': test_pass,
				'pass_new': new_pass,
				'pass_new_conf': 'definitely does not match'
			})
			assertResponse(response, 400, 'Passwords do not match')

		@it('New password must not be empty')
		@patch('util.sendEmail')
		def newPassConfDoesntMatch(_):
			getLoginSession()
			response = app.put('/update/password', headers=csrf_header, json={
				'pass_old': test_pass,
				'pass_new': '',
				'pass_new_conf': ''
			})
			assertResponse(response, 400, 'Invalid password')

		@it('Fields must all be strings')
		@patch('util.sendEmail')
		def allFieldsAreStrings(_):
			getLoginSession()
			response = app.put('/update/password', headers=csrf_header, json={
				'pass_old': [test_pass],
				'pass_new': new_pass,
				'pass_new_conf': new_pass
			})
			assertResponse(response, 400, 'Invalid password')

			response = app.put('/update/password', headers=csrf_header, json={
				'pass_old': test_pass,
				'pass_new': { 'pass': new_pass },
				'pass_new_conf': { 'pass': new_pass }
			})
			assertResponse(response, 400, 'Invalid password')

		@it('Successful password change')
		@patch('util.sendEmail')
		def passwordChangeSuccess(_):
			getLoginSession()
			response = app.put('/update/password', headers=csrf_header, json={
				'pass_old': test_pass,
				'pass_new': new_pass,
				'pass_new_conf': new_pass
			})
			assertResponse(response, 200, 'Ok')

			new_hash = util.hashPassword(new_pass, test_salt)
			user = User.get_by_name(test_name)
			assert_that(user.pass_hash, equal_to(new_hash))

		@it('User notified by email')
		@patch('util.sendEmail')
		def passwordChangeNotifiesByEmail(mock_emailer):
			getLoginSession()
			response = app.put('/update/password', headers=csrf_header, json={
				'pass_old': test_pass,
				'pass_new': new_pass,
				'pass_new_conf': new_pass
			})
			assertResponse(response, 200, 'Ok')

			# Check email was sent with valid code
			args = mock_emailer.call_args[0]
			assert_that(args[0], equal_to(test_email))
			assert_that(args[1], equal_to('%s Password Change Notice' % (config['service_name'])))
			assert_that(args[2], contains_string('change'))
			assert_that(args[2], contains_string('password'))
			assert_that(args[2], contains_string(test_name))

	@describe('Add Email')
	def addEmail():

		csrf_header = None

		@beforeEach
		def _beforeEach():
			nonlocal csrf_header
			with app.session_transaction() as session:
				session.clear()
			testutil.clearDatabase()
			createTestUser()
			csrf_header = { 'X-CSRFToken': getLoginCSRFToken() }

		@it('Invalid session')
		def invalidSession():
			response = app.delete('/update/email', headers=csrf_header)
			assertResponse(response, 403, 'Forbidden')

		@it('Invalid login code')
		def invalidLoginCode():
			getLoginSession()
			with app.session_transaction() as session:
				session['login'] = 'badtoken'
			response = app.delete('/update/email', headers=csrf_header)
			assertResponse(response, 403, 'Forbidden')

		@it('Invalid request data')
		def requestDataInvalid():
			getLoginSession()
			response = app.put('/update/email', headers=csrf_header, data='a@a.a')
			assertResponse(response, 400, 'Missing json data')

		@it('Invalid email')
		def emailInvalid():
			getLoginSession()
			response = app.put('/update/email', headers=csrf_header, json={
				'email': 'bademail'
			})
			assertResponse(response, 400, 'Invalid email')

		@it('Missing email')
		def emailMissing():
			getLoginSession()
			response = app.put('/update/email', headers=csrf_header, json={})
			assertResponse(response, 400, 'Invalid email')

		@it('Missing CSRF token')
		def missingCSRF():
			getLoginSession()
			response = app.put('/update/email', json={ 'email': 'a@a.a'})
			assertResponse(response, 400, 'Session expired. Reload and try again')

		@it('New email matches old email')
		def matchingEmail():
			getLoginSession()
			response = app.put('/update/email', headers=csrf_header, json={
				'email': test_email
			})
			assertResponse(response, 200, 'New email matches old email')

		def extractCodeFromEmail(body):
			match = re.search(r'email\/confirm\/(\w{8})', body)
			assert_that(match, not_none())
			return match.groups()[0]

		@it('PendingEmail records added')
		@patch('util.sendEmail')
		def pendingEmailRecordsAded(mock_emailer):
			getLoginSession()
			email = 'new@email.com'
			response = app.put('/update/email', headers=csrf_header, json={
				'email': email
			})
			assert_that(response.status_code, equal_to(200))
			assert_that(getJsonFrom(response), equal_to({
				'email': test_email,
				'email_pending': email
			}))

			# Check email was sent with valid code
			args = mock_emailer.call_args[0]
			assert_that(args[0], equal_to(email))
			assert_that(args[1], equal_to('%s Email Verification' % (config['service_name'])))
			code = extractCodeFromEmail(args[2])
			assert_that(code, not_none())

			# Check that pivot associating code and user is created too
			pending = PendingEmail.get_by_code(code)
			assert_that(pending, not_none())
			assert_that(pending.email, equal_to(email))
			assert_that(pending.code, equal_to(code))

		@it('Overwriting PendingEmail')
		@patch('util.sendEmail')
		def overwritePendingEmail(mock_emailer):
			getLoginSession()

			# Add two pending emails
			email1 = 'new@email.com'
			response = app.put('/update/email', headers=csrf_header, json={
				'email': email1
			})
			assert_that(response.status_code, equal_to(200))
			assert_that(getJsonFrom(response), equal_to({
				'email': test_email,
				'email_pending': email1
			}))
			code1 = extractCodeFromEmail(mock_emailer.call_args[0][2])
			pending1 = PendingEmail.get_by_code(code1)

			email2 = 'updated@email.com'
			response = app.put('/update/email', headers=csrf_header, json={
				'email': email2
			})
			assert_that(response.status_code, equal_to(200))
			assert_that(getJsonFrom(response), equal_to({
				'email': test_email,
				'email_pending': email2
			}))
			code2 = extractCodeFromEmail(mock_emailer.call_args[0][2])
			pending2 = PendingEmail.get_by_code(code2)

			# The second pending email should overwrite the first
			assert_that(code1, not_(equal_to(code2)))
			assert_that(pending1.code, not_(equal_to(pending2.code)))
			assert_that(pending1.user, equal_to(pending2.user))
			assert_that(pending1.email, equal_to(email1))
			assert_that(pending2.email, equal_to(email2))

			# The old confirm code should also no longer be valid
			assert_that(PendingEmail.get_by_code(code1), none())


	@describe('Confirm email code')
	def confirmEmailCode():

		@beforeEach
		def _beforeEach():
			testutil.clearDatabase()
			createTestUser()
			Code.create(code=test_code)

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
			assert_that(user.email, none())

		@it('Successfully confirm email via code')
		def emailAdded():
			nonlocal test_user
			PendingEmail.create(code=test_code, user=test_user, email=test_email)
			response = app.get('/update/email/confirm/' + test_code)
			assertResponse(response, 200, 'Ok')

			user = User.get_by_id(test_user.id)
			assert_that(user.email, equal_to(test_email))
			assert_that(Code.get_by_code(test_code), none())
			assert_that(PendingEmail.get_by_code(test_code), none())

	@describe('Remove email from user')
	def removeEmailFromUser():

		csrf_header = None

		@beforeEach
		def _beforeEach():
			nonlocal csrf_header
			with app.session_transaction() as session:
				session.clear()
			testutil.clearDatabase()
			createTestUser()
			csrf_header = { 'X-CSRFToken': getLoginCSRFToken() }

		@it('Invalid session')
		def invalidSession():
			response = app.delete('/update/email', headers=csrf_header)
			assertResponse(response, 403, 'Forbidden')

		@it('Invalid login code')
		def invalidLoginCode():
			getLoginSession()
			with app.session_transaction() as session:
				session['login'] = 'badtoken'
			response = app.delete('/update/email', headers=csrf_header)
			assertResponse(response, 403, 'Forbidden')

		@it('Missing CSRF token')
		def missingCSRF():
			getLoginSession()
			response = app.delete('/update/email')
			assertResponse(response, 400, 'Session expired. Reload and try again')

		@it('Successfully removed email')
		def successfulRemoval():
			getLoginSession()

			user = User.get_by_name(test_user.name)
			assert_that(user.email, equal_to(test_email))

			response = app.delete('/update/email', headers=csrf_header)
			assertResponse(response, 200, 'Ok')

			user = User.get_by_name(test_user.name)
			assert_that(user.email, none())

		@it('Succeeds even when there was not an email')
		def successfulNoEmail():
			getLoginSession()
			test_user.email = None
			test_user.save()

			response = app.delete('/update/email', headers=csrf_header)
			assertResponse(response, 200, 'Ok')

			user = User.get_by_name(test_user.name)
			assert_that(user.email, none())

	@describe('Generic Error')
	def genericError():

		@it('Bad Endpoint')
		def badEndpoint():
			response = app.get('/bad/endpoint')
			assertResponse(response, 403, 'Forbidden')

