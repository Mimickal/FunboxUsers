#!/usr/bin/python3
import scrypt

# Let us import db from the project root
import sys
sys.path.append('./')

from db import User

username = 'vulpes'
password = 'vulpes'
salt = 'pickle'
email = 'test@mail.com'

User.create(
	name      = username,
	pass_hash = scrypt.hash(password, salt),
	pass_salt = salt,
	email     = email
)

