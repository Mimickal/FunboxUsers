from db import User, Code

def clearDatabase():
	Code.delete().execute()
	User.delete().execute()

