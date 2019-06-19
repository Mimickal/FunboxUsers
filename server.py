from flask import Flask, request, render_template
from flask_wtf.csrf import CSRFProtect, generate_csrf, validate_csrf
import scrypt
import re
from subprocess import Popen, PIPE
from random import choice
from string import ascii_letters, digits
import os

import db

EMAIL_VALIDATOR = re.compile(r"\"?([-a-zA-Z0-9.`?{}]+@\w+\.\w+)\"?")
CODE_VALIDATOR = re.compile(r'^(\w{8})$')
CODE_SIZE = 8
SECRET_SIZE = 32

app = Flask('Funbox Accounts')
csrf = CSRFProtect(app)

# TODO better place to put this?
# TODO also, maybe pull this out to a utility we can test?
with open('secret.key', 'rb+') as secretFile:
	secret = secretFile.read()
	if not secret:
		secret = os.urandom(SECRET_SIZE)
		secretFile.write(secret)
	app.secret_key = secret


@app.errorhandler(404)
@app.errorhandler(405)
def handle_generic(err):
	return forbidden()

@app.errorhandler(500)
def handle_500(err):
	return 'Internal server error', 500


@app.route('/login', methods=['GET'])
def getLogin():
	return render_template('login.html');


@app.route('/login/form', methods=['POST'])
def userLoginForm():
	form = request.form
	return verifyLogin(form.get('username'), form.get('password'))


@app.route('/login/basic', methods=['POST'])
def userLoginBasic():
	auth = request.authorization
	return verifyLogin(auth.username, auth.password)


@app.route('/login/json', methods=['POST'])
def userLoginJson():
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
		code = makeUniqueCode()
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

def makeUniqueCode():
	global CODE_SIZE
	# Bootleg do-while. Thanks Python.
	while True:
		code = ''.join(choice(ascii_letters + digits) for _ in range(CODE_SIZE))
		if db.getCode(code) is None:
			return code

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
	app.run()

