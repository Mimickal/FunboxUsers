import unittest
import scrypt
from base64 import b64encode

from server import app
import db
from user import User

class ServerTest(unittest.TestCase):

	def setUp(self):
		app.config['TESTING'] = True
		self.app = app.test_client()
		self.test_name = 'ServerTest'
		self.test_pass = 'testpass'
		salt = 'saltything'
		self.headers = authHeader(self.test_name, self.test_pass)
		self.test_user = User(
			name=self.test_name,
			pass_salt=salt,
			pass_hash=scrypt.hash(self.test_pass, salt)
		)

	def tearDown(self):
		db.DB_CONN.execute(
			'DELETE FROM Users WHERE name = ?', [self.test_name]
		)
		db.DB_CONN.commit()


class VerifyTest(ServerTest):

	def setUp(self):
		super().setUp()
		db.addUser(self.test_user)

	def test_verifiesUser(self):
		response = self.app.get('/verify', headers=self.headers)
		with self.subTest():
			self.assertEqual(response.status_code, 200)
			self.assertEqual(response.get_data(as_text=True), 'Ok')

	def test_userDoesNotExist(self):
		response = self.app.get(
			'/verify', headers=authHeader('baduser', 'pass'))
		with self.subTest():
			self.assertEqual(response.status_code, 403)
			self.assertEqual(response.get_data(as_text=True), 'Forbidden')


def authHeader(username, password):
	return {
		'Authorization': 'Basic ' + b64encode(
			bytes(username + ':' + password, 'utf-8')
		).decode('utf-8')
	}


if __name__ == '__main__':
	unittest.main()

