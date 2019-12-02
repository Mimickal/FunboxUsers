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


@app.route('/login', methods=['GET'])
def getLoginPage():
	csrf.protect()
	return route_impl.getLoginPage()

@login_limit
@app.route('/login/form', methods=['POST'])
def userLoginForm():
	csrf.protect()
	return route_impl.userLoginForm()

@login_limit
@app.route('/login/basic', methods=['POST'])
def userLoginBasic():
	return route_impl.userLoginBasic()

@login_limit
@app.route('/login/json', methods=['POST'])
def userLoginJson():
	csrf.protect()
	return route_impl.userLoginJson()

# We could reasonably use a DELETE here, but we're using POST to maintain
# compatibility with older POST-only HTML forms.
@app.route('/logout', methods=['POST'])
def userLogout():
	csrf.protect()
	return route_impl.userLogout()

@app.route('/account', methods=['GET'])
def getAccountPage():
	csrf.protect()
	return route_impl.getAccountPage()

@app.route('/user', methods=['GET'])
def getUser():
	return route_impl.getUser()

@app.route('/update/password', methods=['PUT'])
def changePassword():
	csrf.protect()
	return route_impl.changePassword()

@reset_limit
@app.route('/update/password/reset/<username>', methods=['POST'])
def triggerPasswordChange(username):
	return route_impl.triggerPasswordChange(username)

@confirm_limit
@app.route('/update/password/reset', methods=['PUT'])
def confirmPasswordChange():
	return route_impl.confirmPasswordChange()

@app.route('/update/email', methods=['PUT'])
def updateEmail():
	csrf.protect()
	return route_impl.updateEmail()

@app.route('/update/email/confirm/<code>', methods=['GET'])
def confirmEmail(code):
	return route_impl.confirmEmail(code)

@app.route('/update/email', methods=['DELETE'])
def removeEmail():
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
