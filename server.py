from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFError, CSRFProtect

import config
import route_impl
import util


app = Flask(config.serviceName())
app.secret_key = util.getSecretKey('secret.key')

csrf = CSRFProtect(app)
app.config['WTF_CSRF_CHECK_DEFAULT'] = False

limiter = Limiter(app, key_func=get_remote_address)
login_limit = limiter.shared_limit(config.rateLogin(), scope='login')
reset_limit = limiter.shared_limit(config.rateReset(), scope='reset')
confirm_limit = limiter.shared_limit(config.rateConfirm(), scope='confirm')

Talisman(app,
	force_https=config.devHTTPSEnabled(),
	session_cookie_http_only=True,
	session_cookie_secure=config.devHTTPSEnabled(),
	strict_transport_security=True
)

@app.errorhandler(404)
@app.errorhandler(405)
def handle_generic(err):
	return route_impl.handle_generic(err)

@app.errorhandler(429)
def handle_tooManyRequests(err):
	return route_impl.handle_tooManyRequests(err)

@app.errorhandler(500)
def handle_500(err):
	return route_impl.handle_500(err)

@app.errorhandler(CSRFError)
def handle_CSRFError(err):
	return route_impl.handle_CSRFError(err)

# Endpoints are documented using YAML that matches the OpenAPI spec.
# See https://dev.to/djiit/documenting-your-flask-powered-api-like-a-boss-9eo
#
# The only trick is we're using tabs for indentation, which YAML doesn't like,
# so actually generating HTML docs will require __doc__.replace('\t', '  ').

@app.route('/login', methods=['GET'])
def getLoginPage():
	'''get:
		summary: Gets the login page
		produces:
		- text/html
		responses:
			'200':
				description: The login page
				schema: { type: file }
			'302':
				description: The account page if a user is logged in
				schema: { type: file }
	'''
	csrf.protect()
	return route_impl.getLoginPage()

@login_limit
@app.route('/login/form', methods=['POST'])
def userLoginForm():
	'''post:
		summary: Log in using a legacy-style HTML form post
		consumes:
		- application/x-www-form-urlencoded
		produces:
		- text/html
		- text/plain
		parameters:
		- name: username
		  in: formData
		  type: string
		  required: true
		- name: password
		  in: formData
		  type: string
		  required: true
		- name: csrf_token
		  in: formData
		  type: string
		  required: true
		  description: This is served with the login page
		responses:
			'302':
				description: The users account page on successful login
				schema: { type: file }
			'400':
				description: Missing form fields, or a user is already logged in
				schema: { type: string }
			'403':
				description: User is missing, or password is wrong
				schema: { type: string }
			'429':
				description: Exceeded request rate limit
				schema: { type: string }
	'''
	csrf.protect()
	return route_impl.userLoginForm()

@login_limit
@app.route('/login/basic', methods=['POST'])
def userLoginBasic():
	'''post:
		summary: Log in using basic auth
		produces:
		- text/plain
		parameters:
		- name: username
		  in: header
		  type: string
		  required: true
		- name: password
		  in: header
		  type: string
		  required: true
		responses:
			'200':
				description: Successful login
				schema: { type: string }
			'403':
				description: User is missing, or password is wrong
				schema: { type: string }
	'''
	return route_impl.userLoginBasic()

@login_limit
@app.route('/login/json', methods=['POST'])
def userLoginJson():
	'''post:
		summary: Log in using a JSON request body
		consumes:
		- application/json
		produces:
		- text/html
		- text/plain
		parameters:
		- name: username
		  in: body
		  type: string
		  required: true
		- name: password
		  in: body
		  type: string
		  required: true
		- name: csrf_token
		  in: body
		  type: string
		  required: true
		  description: This is served with the login page
		responses:
			'302':
				description: The users account page on successful login
				schema: { type: file }
			'400':
				description: Missing JSON fields, or a user is already logged in
				schema: { type: string }
			'403':
				description: User is missing, or password is wrong
				schema: { type: string }
			'429':
				description: Exceeded request rate limit
				schema: { type: string }
	'''
	csrf.protect()
	return route_impl.userLoginJson()

# We could reasonably use a DELETE here, but we're using POST to maintain
# compatibility with older POST-only HTML forms.
@app.route('/logout', methods=['POST'])
def userLogout():
	'''post:
		summary: Log out of user account
		produces:
		- text/html
		- text/plain
		responses:
			'302':
				description: The log in page on successful log out
				schema: { type: file }
			'400':
				description: Missing CSRF token
				schema: { type: string }
			'403':
				description: No user was logged in
				schema: { type: string }
	'''
	csrf.protect()
	return route_impl.userLogout()

@app.route('/account', methods=['GET'])
def getAccountPage():
	'''get:
		summary: Gets the account page
		produces:
		- text/html
		responses:
			'200':
				description: The account page
				schema: { type: file }
			'302':
				description: The log in page if a user is not logged in
				schema: { type: file }
	'''
	csrf.protect()
	return route_impl.getAccountPage()

@app.route('/user', methods=['GET'])
def getUser():
	'''get:
		summary: Gets the currently logged in user
		produces:
		- application/json
		- text/plain
		responses:
			'200':
				description: The logged in user
				schema:
					type: object
					properties:
						id: { type: integer }
						name: { type: string }
						email: { type: string }
						email_pending: { type: string }
						created_at: { type: string, format: date-time }
						updated_at: { type: string, format: date-time }
						accessed_at: { type: string, format: date-time }
			'403':
				description: No user is logged in
				schema: { type: string }
	'''
	return route_impl.getUser()

@app.route('/update/password', methods=['PUT'])
def changePassword():
	'''put:
		summary: Change the logged in user's password
		produces
		- text/plain
		parameters:
		- name: pass_old
		  in: body
		  type: string
		  format: password
		  required: true
		- name: pass_new
		  in: body
		  type: string
		  format: password
		  required: true
		- name: pass_new_conf
		  in: body
		  type: string
		  format: password
		  required: true
		responses:
			'200':
				description: Password successfully changed
				schema: { type: string }
			'400':
				description: >
					Missing CSRF token,
					missing JSON fields,
					any given password is invalid,
					old password is incorrect,
					new passwords don't match
				schema: { type: string }
			'403':
				description: No user is logged in
				schema: { type: string }
	'''
	csrf.protect()
	return route_impl.changePassword()

@reset_limit
@app.route('/update/password/reset/<username>', methods=['POST'])
def triggerPasswordChange(username):
	'''post:
		summary: Trigger a password reset for the specified user
		produces:
		- text/plain
		parameters:
		- name: username
		  in: path
		  type: string
		  required: true
		responses:
			'200':
				description: >
					This response is given regardless of whether or not a
					password reset was actually triggered, as a security measure
				schema: { type: string }
			'429':
				description: Exceeded request rate limit
				schema: { type: string }
	'''
	return route_impl.triggerPasswordChange(username)

@confirm_limit
@app.route('/update/password/reset', methods=['PUT'])
def confirmPasswordChange():
	'''put:
		summary: Reset a user's password
		consumes:
		- application/json
		produces:
		- text/plain
		parameters:
		- name: reset_code
		  in: body
		  type: string
		  required: true
		  description: Served in the password reset email
		- name: pass_new
		  in: body
		  type: string
		  format: password
		  required: true
		- name: pass_new_conf
		  in: body
		  type: string
		  format: password
		  required: true
		responses:
			'200':
				description: Password successfully reset
				schema: { type: string }
			'400':
				description: Missing form data, invalid / non-matching passwords
				schema: { type: string }
			'403':
				description: Invalid password reset code
				schema: { type: string }
			'429':
				description: Exceeded request rate limit
				schema: { type: string }
	'''
	return route_impl.confirmPasswordChange()

@app.route('/update/email', methods=['PUT'])
def updateEmail():
	'''put:
		summary: Change the logged in user's email
		consumes:
		- application/json
		produces:
		- application/json
		- text/plain
		parameters:
		- name: email
		  in: body
		  type: string
		  format: email
		  required: true
		responses:
			'200':
				description: >
					Logged in user's email matches the new email. If the new
					email matches the current email, nothing actually changes.
				schema:
					# Returns a plain string if old and new emails match
					type: object
					properties:
						email: { type: string, format: email }
						email_pending: { type: string, format: email }
			'400':
				description: Missing CSRF token, Missing / invalid email in form
				schema: { type: string }
			'403':
				description: No user is logged in
				schema: { type: string }
	'''
	csrf.protect()
	return route_impl.updateEmail()

@app.route('/update/email/confirm/<code>', methods=['GET'])
def confirmEmail(code):
	'''get:
		summary: Confirm a user's pending email
		produces:
		- text/html
		- text/plain
		parameters:
		- name: code
		  in: path
		  type: string
		  required: true
		responses:
			'200':
				description: The email confirmation page
				schema: { type: file }
			'403':
				description: Invalid email confirm code
				schema: { type: string }
	'''
	return route_impl.confirmEmail(code)

@app.route('/update/email', methods=['DELETE'])
def removeEmail():
	'''delete:
		summary: Remove the logged in user's email
		produces:
		- text/plain
		responses:
			'200':
				description: Email successfully removed
				schema: { type: string }
			'400':
				description: Missing CSRF token
				schema: { type: string }
			'403':
				description: No user is logged in
				schema: { type: string }
	'''
	csrf.protect()
	return route_impl.removeEmail()


if __name__ == '__main__':
	# This is actually just HTTPS for Flask's development server.
	# Production uses HTTP with HTTPS offloaded to Apache via a WSGI app.
	context=None
	if config.devHTTPSEnabled():
		context = (config.devHTTPSCertFile(), config.devHTTPSKeyFile())

	app.run(
		host=config.host(),
		port=config.port(),
		debug=config.debug(),
		ssl_context=context
	)
