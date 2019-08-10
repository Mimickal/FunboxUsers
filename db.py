from peewee import *
from datetime import datetime, timedelta
from os import environ

DB_NAME = environ.get('FB_USERS_DB', 'fbusers.db')
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
	created_at = DateTimeField(default=datetime.now())
	used_at    = DateTimeField(null=True)

	# This is all for automatic conversion to strings.
	def __str__(self):
		return self.code
	def __add__(self, other):
		return self.code + other
	def __radd__(self, other):
		return other + self.code
	def __eq__(self, other):
		if isinstance(other, str):
			return self.code == other
		return super(Code, self).__eq__(other)

	def get_by_code(code, include_used=False):
		query = Code.select().where(Code.code == str(code))
		if not include_used:
			query = query.where(Code.used_at.is_null())
		try:
			return query.get()
		except DoesNotExist:
			return None

	def use_code(code):
		'''Sets a code's used_at field, effectively marking it as used.'''
		Code.update(used_at=datetime.now()).where(Code.code == str(code)).execute()

	def cull_old_codes():
		'''Deletes all old, unused codes.'''
		two_days_ago = datetime.now() - timedelta(days=2)
		return Code.delete().where(
			Code.used_at.is_null(),
			Code.created_at < two_days_ago
		).execute()

	def num_codes_with_len(length):
		'''Returns the number of codes with the given length'''
		return Code                                \
			.select(fn.COUNT(1).alias('count'))    \
			.where(fn.LENGTH(Code.code) == length) \
			.get().count

class CodePivot(BaseModel):
	'''Base class for tables that associate codes with other things'''
	code = ForeignKeyField(Code, null=False, unique=True, field=Code.code)
	user = ForeignKeyField(User, null=False, unique=True)

	@classmethod
	def get_by_user(subclass, user):
		try:
			return subclass.select().where(subclass.user == user).get()
		except DoesNotExist:
			return None

	@classmethod
	def get_by_code(subclass, code):
		try:
			return subclass.select().where(subclass.code == str(code)).get()
		except DoesNotExist:
			return None

	@classmethod
	def upsert(subclass, **kwargs):
		code = kwargs.pop('code', None)
		if code is not None:
			kwargs['code'] = str(code)
		return subclass.insert(kwargs).on_conflict_replace().execute()

class PendingEmail(CodePivot):
	email = TextField(null=False)

class LoginCode(CodePivot):
	pass

db.connect()
db.create_tables([User, Code, PendingEmail, LoginCode])

