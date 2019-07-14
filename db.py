from peewee import *
from datetime import datetime, timedelta

DB_NAME = 'fbusers.db'
CODE_TYPE_PASS = 'pass'
CODE_TYPE_EMAIL = 'email'

db = SqliteDatabase(DB_NAME, pragmas={'foreign_keys': 1})

class BaseModel(Model):
	class Meta:
		database = db

class User(BaseModel):
	id          = AutoField()
	name        = TextField(null=False, unique=True)
	pass_hash   = BlobField(null=False)
	pass_salt   = TextField(null=False)
	email       = TextField(null=True)
	created_at  = DateTimeField(default=datetime.now)
	updated_at  = DateTimeField(default=datetime.now)
	accessed_at = DateTimeField(default=datetime.now)

	def get_by_name(name):
		'''Gets a user by their name.'''
		try:
			return User.select().where(User.name == name).get()
		except DoesNotExist:
			return None

	def save(self, *args, **kwargs):
		timestamp = datetime.now()
		self.updated_at = timestamp
		self.accessed_at = timestamp
		return super(User, self).save(*args, **kwargs)

class Code(BaseModel):
	code       = TextField(null=False, unique=True, constraints=[Check("code != ''")])
	user       = ForeignKeyField(User, null=False)
	type       = TextField(null=False)
	email      = TextField(null=True)
	created_at = DateTimeField(default=datetime.now())
	used_at    = DateTimeField(null=True)

	def create_email(*args, **kwargs):
		if kwargs.get('email', None) is None:
			raise IntegrityError('Email codes must define an email')
		kwargs['type'] = 'email'
		return Code.create(*args, **kwargs)

	def create_password(*args, **kwargs):
		kwargs['type'] = 'pass'
		return Code.create(*args, **kwargs)

	def get_by_code(code):
		try:
			return Code.select().where(
				Code.code == code,
				Code.used_at == None
			).get()
		except DoesNotExist:
			return None

	def use_code(code):
		'''Sets a code's used_at field, effectively marking it as used.'''
		Code.update(used_at=datetime.now()).where(code == code).execute()

	def cull_old_codes():
		'''Deletes all old, unused codes.'''
		two_days_ago = datetime.now() - timedelta(days=2)
		return Code.delete().where(
			Code.used_at == None,
			Code.created_at < two_days_ago
		).execute()

db.connect()
db.create_tables([User, Code])

