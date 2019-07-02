from flask import Flask, request, render_template
from flask_wtf.csrf import CSRFProtect, CSRFError
import scrypt
import re
from subprocess import Popen, PIPE
from random import choice
from string import ascii_letters, digits
import yaml
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import db
import util

EMAIL_VALIDATOR = re.compile(r"\"?([-a-zA-Z0-9.`?{}]+@\w+\.\w+)\"?")
CODE_VALIDATOR = re.compile(r'^(\w{8})$')
CODE_SIZE = 8

app = Flask('Funbox Accounts')
app.secret_key = util.getSecretKey('secret.key')

config = yaml.safe_load(open('config.yaml'))

csrf = CSRFProtect(app)
app.config['WTF_CSRF_ENABLED'] = False

limiter = Limiter(app, key_func=get_remote_address)
login_limit = limiter.shared_limit(config['rate_login'], scope='login')


@app.errorhandler(404)
@app.errorhandler(405)
def handle_generic(err):
	return forbidden()

@app.errorhandler(429)
def handle_tooManyRequests(err):
	return 'Too many requests', 429

@app.errorhandler(500)
def handle_500(err):
	return 'Internal server error', 500

@app.errorhandler(CSRFError)
def handle_CSRFError(err):
	# TODO log the real error probably
	return 'Session expired. Reload and try again', 400


@app.route('/login', methods=['GET'])
def getLogin():
	csrf.protect()
	return render_template('login.html');


@login_limit
@app.route('/login/form', methods=['POST'])
def userLoginForm():
	csrf.protect()
	form = request.form
	return verifyLogin(form.get('username'), form.get('password'))


@login_limit
@app.route('/login/basic', methods=['POST'])
def userLoginBasic():
	auth = request.authorization
	return verifyLogin(auth.username, auth.password)


@login_limit
@app.route('/login/json', methods=['POST'])
def userLoginJson():
	csrf.protect()
	json = request.json
	return verifyLogin(json['username'], json['password'])


def verifyLogin(username, password):
	user = db.getUser(username)

	# Return 403 instead of a 404 to make list of users harder to brute force
	if user is None:
		return forbidden()

	pw_hash = scrypt.hash(password, user.get('pass_salt'))

	if pw_hash == user.get('pass_hash'):
		return ok()
	else:
		return forbidden()


@app.route('/update/email', methods=['PUT'])
def addEmail():
	global EMAIL_VALIDATOR
	global CODE_SIZE
	auth = request.authorization
	user = db.getUser(auth.username)
	email = request.get_data(as_text=True)

	if user is None:
		return forbidden()

	if EMAIL_VALIDATOR.match(email) is None:
		return 'Invalid email', 400

	pw_hash = scrypt.hash(auth.password, user.get('pass_salt'))

	if pw_hash == user.get('pass_hash'):
		# Create an email verify code
		code = util.makeUniqueCode(CODE_SIZE)
		db.addEmailCode(code, user.get('id'), email)

		# TODO we're hard coding this link for now
		link = 'https://funbox.com.ru:20100/update/email/confirm/' + code
		sendmail(email, 'Funbox Email Verification',
			'Hello from funbox! Use this link to verify your email: ' + link)

		return ok()
	else:
		return forbidden()


@app.route('/update/email/confirm/<code>', methods=['GET'])
def confirmEmail(code):
	global CODE_VALIDATOR

	if CODE_VALIDATOR.match(code) is None:
		return forbidden()

	code_info = db.getCode(code)
	if code_info is None:
		return forbidden()

	user = db.getUserById(code_info.get('user_id'))
	if user is None:
		return forbidden()

	user['email'] = code_info.get('email')
	db.updateUser(user)
	db.useCode(code_info.get('code'))

	return ok()


def ok():
	return 'Ok', 200

def forbidden():
	return 'Forbidden', 403

def sendmail(email, subject, message):
	post = "\n\n\nNote: This is an automated email. " + \
		'Maybe we read responses, or maybe we pipe them to /dev/null'
	proc = Popen([
		'/usr/bin/mail',
		'-s', subject,
		email
	], stdin=PIPE)
	proc.communicate(input=bytes(message + post, 'UTF-8'))


if __name__ == '__main__':
	app.run(host=config['host'], port=config['port'], debug=config['debug'])

