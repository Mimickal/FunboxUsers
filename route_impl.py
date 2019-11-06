import html
import re

from flask import jsonify, redirect, render_template, request, session
from playhouse.shortcuts import model_to_dict

import config
from db import Code, LoginCode, PasswordReset, PendingEmail, User
import util


CODE_VALIDATOR = re.compile(r'^(\w{8})$')
CODE_SIZE = 8
LOGIN_COOKIE_SIZE = 16
NAME = config.serviceName()


def handle_generic(err):
	return forbidden()

def handle_tooManyRequests(err):
	return 'Too many requests', 429

def handle_500(err):
	return 'Internal server error', 500

def handle_CSRFError(err):
	# TODO log the real error probably
	return 'Session expired. Reload and try again', 400


def getLoginPage():
	if LoginCode.get_by_code(session.get('login')):
		return redirect('/account')
	else:
		return render_template('login.html')


def userLoginForm():
	# form will never be None, otherwise CSRF protection will trigger
	form = request.form
	try:
		username = form['username']
		password = form['password']
	except KeyError:
		return 'Missing username / password in form body', 400

	return verifyLogin(username, password, cookie=True)


def userLoginBasic():
	auth = request.authorization
	return verifyLogin(auth.username, auth.password)


def userLoginJson():
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

	pw_hash = util.hashPassword(password, user.pass_salt)

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


def userLogout():
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


def getAccountPage():
	if LoginCode.get_by_code(session.get('login')):
		return render_template('account.html')
	else:
		return redirect('/login')


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


def changePassword():
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
	old_hash = util.hashPassword(old, user.pass_salt)
	if old_hash != user.pass_hash:
		return 'Old password incorrect', 400

	if new1 != new2:
		return 'Passwords do not match', 400

	new_hash = util.hashPassword(new1, user.pass_salt)
	user.pass_hash = new_hash
	user.save()

	if user.email:
		util.sendEmail(user.email, '%s Password Change Notice' % (NAME),
			'Hello from %s! The password for %s was just changed. '
			'If this was not your doing then now is the time to scream.'
			% (NAME, html.escape(user.name)))

	return ok()


def triggerPasswordChange(username):
	user = User.get_by_name(username)

	if user and user.email:
		code_str = util.makeUniqueCode(CODE_SIZE)
		code = Code.get_by_code(code_str)
		PasswordReset.create(user=user, code=code)

		link = util.getFullLink('update/password/reset/', code)
		util.sendEmail(user.email, NAME + ' Password Reset',
			'Hello from ' + NAME + '!\n'
			'A password reset was requested for the account attached to this '
			'email. If you requested this, use this link: ' + link + '\n\n'
			'If you didn\'t request this, please ignore this email.'
		)

	# Always return this even if the user doesn't exist or have an email.
	# Helps prevent sussing out a list of users.
	return 'Reset email sent', 200


def confirmPasswordChange():
	json = request.json
	if json is None:
		return 'Missing json data', 400

	code = json.get('reset_code')
	password_reset = PasswordReset.get_by_code(code)
	if not password_reset:
		return forbidden()

	new1 = json.get('pass_new')
	new2 = json.get('pass_new_conf')

	if not util.isValidPassword(new1) or not util.isValidPassword(new2):
		return 'Invalid password', 400

	if new1 != new2:
		return 'Passwords do not match', 400

	user = password_reset.user
	user.pass_hash = util.hashPassword(new1, user.pass_salt)
	user.save()
	Code.use_code(code)
	password_reset.delete_instance()

	return ok()


def updateEmail():
	global CODE_SIZE

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

	if not util.isValidEmail(email):
		return 'Invalid email', 400

	if email == user.email:
		return 'New email matches old email', 200

	# Create an email verify code
	code_str = util.makeUniqueCode(CODE_SIZE)
	code = Code.get_by_code(code_str)
	PendingEmail.upsert(code=code, user=user, email=email)

	link = util.getFullLink('update/email/confirm/', code)
	util.sendEmail(email, '%s Email Verification' % (NAME),
		'Hello from %s! Use this link to verify your email: %s'
		 % (NAME, link))

	return jsonify({
		'email': user.email,
		'email_pending': email
	})


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
	pending.delete_instance()

	return render_template('email.html')


def removeEmail():
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

