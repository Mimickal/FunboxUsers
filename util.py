import os
from string import ascii_letters, digits
from random import choice

import db

SECRET_SIZE = 32

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
	return ''.join(choice(ascii_letters + digits) for _ in range(length))

def makeUniqueCode(length):
	'''Creates a unique random code. Uses DB to ensure uniqueness'''
	# Bootleg do-while. Thanks Python.
	while True:
		code = makeCode(length)
		if db.getCode(code) is None:
			return code

