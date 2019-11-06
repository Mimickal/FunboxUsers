from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFError, CSRFProtect

import route_impl
import util

DEFAULT_CONFIG_PATH = 'config.yaml'

# The reason for including this up here instead of down below is so we can
# non-intrusively change some constants before they are used.

# temp vars:
config_path = DEFAULT_CONFIG_PATH

if __name__ == '__main__':
	from argparse import ArgumentParser

	# Initialize startup arguments
	parser = ArgumentParser(description='FunboxUsers Account server')
	parser.add_argument(
		'--config-path', metavar='config_path', type=str,
		help='Path to the config yaml. DEFAULT='+DEFAULT_CONFIG_PATH,
		default=DEFAULT_CONFIG_PATH
	)
	args = parser.parse_args()

	config_path = args.config_path

config = util.loadYaml(config_path)
del config_path

NAME = config['service_name']

app = Flask(NAME)
app.secret_key = util.getSecretKey('secret.key')

csrf = CSRFProtect(app)
app.config['WTF_CSRF_CHECK_DEFAULT'] = False

limiter = Limiter(app, key_func=get_remote_address)
login_limit = limiter.shared_limit(config['rate_login'], scope='login')
reset_limit = limiter.shared_limit(config['rate_reset'], scope='reset')
confirm_limit = limiter.shared_limit(config['rate_confirm'], scope='confirm')


Talisman(app,
	force_https=config['https']['enabled'],
	session_cookie_http_only=True,
	session_cookie_secure=config['https']['enabled'],
	strict_transport_security=True
)

@app.errorhandler(404)
@app.errorhandler(405)
def handle_generic(err):
	return 'Forbidden', 403

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
	context=None
	if config['https']['enabled']:
		context = (config['https']['cert_file'], config['https']['key_file'])

	app.run(
		host=config['host'],
		port=config['port'],
		debug=config['debug'],
		ssl_context=context
	)
