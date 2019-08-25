#!/usr/bin/python3
# Let us import db from the project root
import sys
sys.path.append('./')

from db import User
from util

username = 'vulpes'
password = 'vulpes'
salt = 'pickle'
email = 'test@mail.com'

User.create(
	name      = username,
	pass_hash = util.hashPassword(password, salt),
	pass_salt = salt,
	email     = email
)

