from db import User, Code, PendingEmail, LoginCode

def clearDatabase():
	LoginCode.delete().execute()
	PendingEmail.delete().execute()
	Code.delete().execute()
	User.delete().execute()

