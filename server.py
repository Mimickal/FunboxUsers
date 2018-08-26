from flask import Flask

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
	return error.message, error.http_code


@app.route('/verify')
def verifyUser():
	pass


if __name__ == '__main__':
	app.run()

