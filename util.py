import os

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
