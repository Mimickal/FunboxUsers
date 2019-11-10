import os
from random import choice
import re
import posixpath
import socket
import string
from subprocess import PIPE, Popen
import yaml

from peewee import IntegrityError
import scrypt

from db import User, Code

SECRET_SIZE = 32
CODE_CHARS = string.ascii_letters + string.digits
CODE_EXTRACTOR = re.compile(r'^(\w+)$')
EMAIL_VALIDATOR = re.compile(r"\"?([-+a-zA-Z0-9.`?{}/|]+@\w+\.\w+)\"?")

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

def isValidCode(code_str):
	return _matchCode(code_str) is not None

def isValidCodeWithLength(code_str, length):
	if not isinstance(length, int):
		raise TypeError('length is not an int')
	match = _matchCode(code_str)
	return match is not None and len(match.group(1)) == length

def _matchCode(code_str):
	global CODE_EXTRACTOR

	if not isinstance(code_str, str):
		code_str = ''

	return CODE_EXTRACTOR.match(code_str)

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

def isValidEmail(email):
	'''Returns whether or not this is a valid email'''
	global EMAIL_VALIDATOR
	if not isinstance(email, str):
		email = ''
	return bool(EMAIL_VALIDATOR.match(email))

def hashPassword(password, salt):
	'''Hashes the given password using the given salt'''
	return scrypt.hash(password, salt)

def loadYaml(yaml_file):
	'''Safely load the given YAML file into a nested Python dict'''
	with open(yaml_file) as fileobj:
		return yaml.safe_load(fileobj)

def getFqdn():
	'''Gets fqdn that always ends with /'''
	name = socket.getfqdn()
	if not name.endswith('/'):
		name += '/'
	return name

def getFullLink(*args):
	'''Takes a relative link or multiple pieces of a relative link and returns
	a full link containining the fqdn'''
	# Parsing it into a new list, because you cannot edit args directly.
	parts = [getFqdn()]
	for arg in args:
		# the lstrip is so that the posixpath.join function does not interpret
		# any pieces in the middle as the root and cuts the path in half
		# Confused? Yeah me too.
		parts.append(str(arg).lstrip("/"))
	return posixpath.join(*parts)
