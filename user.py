class User:
	'''A container for a funbox user.'''
	def __init__(self, name, pass_hash, pass_salt, id=None, \
	email=None, created_at=None, updated_at=None, accessed_at=None):
		self.id = id
		self.name = name
		self.pass_hash = pass_hash
		self.pass_salt = pass_salt
		self.email = email
		self.created_at = created_at
		self.updated_at = updated_at
		self.accessed_at = accessed_at

