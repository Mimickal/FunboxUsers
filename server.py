from flask import Flask, request
import scrypt
import re
from subprocess import Popen, PIPE

from user import User
import db

app = Flask('Funbox Accounts')
EMAIL_VALIDATOR = re.compile(r"\"?([-a-zA-Z0-9.`?{}]+@\w+\.\w+)\"?")


@app.errorhandler(404)
@app.errorhandler(405)
def handle_generic(err):
	return forbidden()

@app.errorhandler(500)
def handle_500(err):
	return 'Internal server error', 500


@app.route('/verify', methods=['GET'])
def verifyUser():
	auth = request.authorization
	user = db.getUser(auth.username)

	# Return 403 instead of a 404 to make list of users harder to brute force
	if user is None:
		return forbidden()

	pw_hash = scrypt.hash(auth.password, user.pass_salt)

	if pw_hash == user.pass_hash:
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

	pw_hash = scrypt.hash(auth.password, user.pass_salt)

	if pw_hash == user.pass_hash:
		user.email = email
		db.updateUser(user)
		return ok()
	else:
		return forbidden()


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
	app.run()

