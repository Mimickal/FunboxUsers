import os
import string
from subprocess import Popen, PIPE
from random import choice
from peewee import IntegrityError

from db import User, Code

SECRET_SIZE = 32
CODE_CHARS = string.ascii_letters + string.digits

def getSecretKey(key):
	'''Load a secret key, creating it if it doesn't exist'''
	global SECRET_SIZE
	if not key:
		raise Exception('Empty key path')

	try:
		return _getSecretKey(key)
	except FileNotFoundError:
		os.makedirs(os.path.dirname(key), exist_ok=True)
		return _getSecretKey(key)

# Helper for actually creating the key in getSecretKey
def _getSecretKey(key):
	with open(key, 'ab+') as secretFile:
		secretFile.seek(0)
		secret = secretFile.read()
		if not secret:
			secret = os.urandom(SECRET_SIZE)
			secretFile.write(secret)
	return secret

def makeCode(length):
	'''Creates a random code'''
	global CODE_CHARS
	if length < 0:
		raise Exception('Tried to make a code with length %d' % length)
	return ''.join(choice(CODE_CHARS) for _ in range(length))

def makeUniqueCode(length):
	'''Creates a unique random code. Uses DB to ensure uniqueness'''
	global CODE_CHARS

	# Catch the absurdly unlikely case that we actually run out of codes
	max_combos = len(CODE_CHARS) ** length
	current_combos = Code.num_codes_with_len(length)
	if current_combos >= max_combos:
		raise Exception('No remaining unique codes available of length %d' % length)

	# Bootleg do-while. Thanks Python.
	# Create the code in a try-except to prevent creation race condition
	while True:
		code = makeCode(length)
		try:
			Code.create(code=code)
			return code
		except IntegrityError:
			continue

def isValidPassword(password):
	'''Validates that a password is a defined, non-empty string'''
	return password is not None \
		and len(password) > 0  \
		and isinstance(password, str)

def sendEmail(email, subject, message):
	'''Sends an email using the system's email handler'''
	post = "\n\n\nNote: This is an automated email. " + \
		'Maybe we read responses, or maybe we pipe them to /dev/null'
	if os.path.isfile('/usr/bin/mail'):
		proc = Popen([
			'/usr/bin/mail',
			'-s', subject,
			email
		], stdin=PIPE)
		proc.communicate(input=bytes(message + post, 'UTF-8'))
	else:
		print(
			'Mock sending email\nTo:      {:s}\nSubject: {:s}\nBody:\n {:s}' \
			.format(email, subject, message + post)
		)

