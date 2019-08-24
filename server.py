import html
from random import choice
import re
from string import ascii_letters, digits
import socket
import yaml

from flask import Flask, jsonify, redirect, render_template, request, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFError, CSRFProtect,
from playhouse.shortcuts import model_to_dict
import scrypt

from db import Code, LoginCode, PendingEmail, User
import util


EMAIL_VALIDATOR = re.compile(r"\"?([-a-zA-Z0-9.`?{}]+@\w+\.\w+)\"?")
CODE_VALIDATOR = re.compile(r'^(\w{8})$')
CODE_SIZE = 8
LOGIN_COOKIE_SIZE = 16

NAME = 'Funbox'

app = Flask('Funbox Accounts')
app.secret_key = util.getSecretKey('secret.key')

config = yaml.safe_load(open('config.yaml'))

csrf = CSRFProtect(app)
app.config['WTF_CSRF_CHECK_DEFAULT'] = False

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

	if LoginCode.get_by_code(session.get('login')):
		return redirect('/account')
	else:
		return render_template('login.html')


@login_limit
@app.route('/login/form', methods=['POST'])
def userLoginForm():
	csrf.protect()

	# form will never be None, otherwise CSRF protection will trigger
	form = request.form
	try:
		username = form['username']
		password = form['password']
	except KeyError:
		return 'Missing username / password in form body', 400

	return verifyLogin(username, password, cookie=True)


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

	if json is None:
		return 'Missing JSON body', 400

	try:
		username = json['username']
		password = json['password']
	except KeyError:
		return 'Missing username / password in JSON body', 400
	except TypeError:
		return 'Malformed JSON body', 400

	return verifyLogin(username, password, cookie=True)


def verifyLogin(username, password, cookie=False):
	global LOGIN_COOKIE_SIZE

	if session.get('login', None) is not None:
		return 'Already logged in', 400

	user = User.get_by_name(username)

	# Return 403 instead of a 404 to make list of users harder to brute force
	if user is None:
		return forbidden()

	pw_hash = scrypt.hash(password, user.pass_salt)

	if pw_hash == user.pass_hash:
		if cookie:
			code_str = util.makeUniqueCode(LOGIN_COOKIE_SIZE)
			code = Code.get_by_code(code_str)
			LoginCode.upsert(user=user, code=code_str)
			session['login'] = code_str
			return redirect('/account')
		else:
			return ok()
	else:
		return forbidden()


# We could reasonably use a DELETE here, but we're using POST to maintain
# compatibility with older POST-only HTML forms.
@app.route('/logout', methods=['POST'])
def logout():
	csrf.protect()

	login_code = session.get('login', None)
	if login_code is None:
		return forbidden()

	login = LoginCode.get_by_code(login_code)
	if login is None:
		return forbidden()

	login.delete_instance()
	Code.use_code(login_code)
	session.pop('login')
	return redirect('/login')


@app.route('/account', methods=['GET'])
def getAccount():
	csrf.protect()

	if LoginCode.get_by_code(session.get('login')):
		return render_template('account.html')
	else:
		return redirect('/login')


@app.route('/user', methods=['GET'])
def getUser():
	login_code = session.get('login', None)
	if login_code is None:
		return forbidden()

	login = LoginCode.get_by_code(login_code)
	if login is None:
		return forbidden()

	user = login.user

	info = model_to_dict(user)
	info.pop('pass_hash', None)
	info.pop('pass_salt', None)

	pending = PendingEmail.get_by_user(user)
	if pending is not None:
		info['email_pending'] = pending.email

	return jsonify(info), 200


@app.route('/update/password', methods=['PUT'])
def changePassword():
	csrf.protect()

	login_code = session.get('login', None)
	if login_code is None:
		return forbidden()

	login = LoginCode.get_by_code(login_code)
	if login is None:
		return forbidden()

	json = request.json
	if json is None:
		return 'Missing json data', 400

	old = json.get('pass_old', None)
	new1 = json.get('pass_new', None)
	new2 = json.get('pass_new_conf', None)

	if old is None or new1 is None or new2 is None:
		return 'Missing fields', 400

	if not util.isValidPassword(old) or not util.isValidPassword(new1):
		return 'Invalid password', 400

	user = login.user
	old_hash = scrypt.hash(old, user.pass_salt)
	if old_hash != user.pass_hash:
		return 'Old password incorrect', 400

	if new1 != new2:
		return 'Passwords do not match', 400

	new_hash = scrypt.hash(new1, user.pass_salt)
	user.pass_hash = new_hash
	user.save()

	if user.email:
		# TODO Unhardcode name
		util.sendEmail(user.email, 'Funbox Password Change Notice',
			'Hello from funbox! The password for %s was just changed. '
			'If this was not your doing then now is the time to scream.'
			% (html.escape(user.name)))

	return ok()


@app.route('/update/email', methods=['PUT'])
def addEmail():
	global EMAIL_VALIDATOR
	global CODE_SIZE

	csrf.protect()

	login_code = session.get('login', None)
	if login_code is None:
		return forbidden()

	login = LoginCode.get_by_code(login_code)
	if login is None:
		return forbidden()

	user = login.user
	json = request.json
	if json is None:
		return 'Missing json data', 400

	email = json.get('email')

	# TODO pull this validation out to utils, and make it return True/False
	if not email or not EMAIL_VALIDATOR.match(email):
		return 'Invalid email', 400

	if email == user.email:
		return 'New email matches old email', 200

	# Create an email verify code
	code_str = util.makeUniqueCode(CODE_SIZE)
	code = Code.get_by_code(code_str)
	PendingEmail.upsert(code=code, user=user, email=email)

	link = socket.getfqdn() + 'update/email/confirm/' + code
	util.sendEmail(email, NAME + ' Email Verification',
		'Hello from ' + NAME + '! Use this link to verify your email: ' + link)

	return jsonify({
		'email': user.email,
		'email_pending': email
	})


@app.route('/update/email/confirm/<code>', methods=['GET'])
def confirmEmail(code):
	global CODE_VALIDATOR
	if CODE_VALIDATOR.match(code) is None:
		return forbidden()

	pending = PendingEmail.get_by_code(code)
	if pending is None:
		return forbidden()

	user = pending.user
	# With peewee this shouldn't ever happen
	if user is None:
		return forbidden()

	user.email = pending.email
	user.save()
	Code.use_code(code)
	pending.delete()

	return ok()


@app.route('/update/email', methods=['DELETE'])
def removeEmail():
	csrf.protect()
	code = session.get('login', None)
	if code is None:
		return forbidden()

	login = LoginCode.get_by_code(code)
	if login is None:
		return forbidden()

	login.user.email = None
	login.user.save()

	return ok()


def ok():
	return 'Ok', 200

def forbidden():
	return 'Forbidden', 403


if __name__ == '__main__':
	app.run(host=config['host'], port=config['port'], debug=config['debug'])

