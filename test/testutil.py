from db import User, Code, PendingEmail

def clearDatabase():
	PendingEmail.delete().execute()
	Code.delete().execute()
	User.delete().execute()

