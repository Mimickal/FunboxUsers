from db import Code, LoginCode, PendingEmail, User

def clearDatabase():
	LoginCode.delete().execute()
	PendingEmail.delete().execute()
	Code.delete().execute()
	User.delete().execute()

