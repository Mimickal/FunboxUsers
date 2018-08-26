class User:
	'''A container for a funbox user.

	Field order should match the order in the Users SQL table,
	so tuple expansion doesn't break.
	'''
	def __init__(self, id, name, pass_hash, pass_salt, \
	email, created_at, updated_at, accessed_at):
		self.id = id
		self.name = name
		self.pass_hash = pass_hash
		self.pass_salt = pass_salt
		self.email = email
		self.created_at = created_at
		self.updated_at = updated_at
		self.accessed_at = accessed_at

