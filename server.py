from flask import Flask, request
import scrypt

from user import User
import db

app = Flask('Funbox Accounts')

class AccountException(Exception):
    '''General purpose error Flask can catch'''
    def __init__(self, http_code, message):
        self.http_code = http_code
        self.message = message

@app.errorhandler(AccountException)
def handleAccountException(exception):
	'''Override Flask's default behavior for unexpected exceptions,
	so we can send a pure data response instead of rendered HTML.
	'''
	return exception.message, exception.http_code


@app.route('/verify', methods=['GET'])
def verifyUser():
	auth = request.authorization
	user = db.getUser(auth.username)

	# Return 403 instead of a 404 to make list of users harder to brute force
	if user is None:
		return "Forbidden", 403

	pw_hash = scrypt.hash(auth.password, user.pass_salt)

	if pw_hash == user.pass_hash:
		return "Ok", 200
	else:
		return "Forbidden", 403


if __name__ == '__main__':
	app.run()

