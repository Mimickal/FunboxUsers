from db import Code, LoginCode, PasswordReset, PendingEmail, User

def clearDatabase():
	LoginCode.delete().execute()
	PendingEmail.delete().execute()
	PasswordReset.delete().execute()
	Code.delete().execute()
	User.delete().execute()

