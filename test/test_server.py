import unittest
from unittest.mock import patch
import scrypt
from base64 import b64encode
import re

from server import app, makeUniqueCode
import db

class ServerTest(unittest.TestCase):

	def setUp(self):
		app.config['TESTING'] = True
		self.app = app.test_client()
		self.test_name = 'ServerTest'
		self.test_pass = 'testpass'
		salt = 'saltything'
		self.headers = authHeader(self.test_name, self.test_pass)
		self.test_user = {
			'name': self.test_name,
			'pass_salt': salt,
			'pass_hash': scrypt.hash(self.test_pass, salt)
		}

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

	def test_passDoesNotMatch(self):
		response = self.app.get(
			'/verify', headers=authHeader(self.test_name, 'badpass'))
		with self.subTest():
			self.assertEqual(response.status_code, 403)
			self.assertEqual(response.get_data(as_text=True), 'Forbidden')


class AddEmailTest(ServerTest):

	def setUp(self):
		super().setUp()
		self.test_id = db.addUser(self.test_user)

	def test_userDoeNotExist(self):
		response = self.app.put(
			'/update/email',
			headers=authHeader('baduser', 'pass'),
			data='example@email.com')
		with self.subTest():
			self.assertEqual(response.status_code, 403)
			self.assertEqual(response.get_data(as_text=True), 'Forbidden')

	def test_passDoesNotMatch(self):
		response = self.app.put(
			'/update/email',
			headers=authHeader(self.test_name, 'badpass'),
			data='example@email.com')
		with self.subTest():
			self.assertEqual(response.status_code, 403)
			self.assertEqual(response.get_data(as_text=True), 'Forbidden')

	def test_emailInvalid(self):
		response = self.app.put(
			'/update/email', headers=self.headers, data='bademail')
		with self.subTest():
			self.assertEqual(response.status_code, 400)
			self.assertEqual(response.get_data(as_text=True), 'Invalid email')

	@patch('server.sendmail')
	def test_codeAdded(self, mock_emailer):
		email = 'new@email.com'
		response = self.app.put(
			'/update/email', headers=self.headers, data=email)
		with self.subTest():
			self.assertEqual(response.status_code, 200)
			self.assertEqual(response.get_data(as_text=True), 'Ok')

			args = mock_emailer.call_args[0]
			self.assertEqual(args[0], email)
			self.assertEqual(args[1], 'Funbox Email Verification')

			# Check that our confirm link contains a valid code
			match = re.search(r'email\/confirm\/(\w{8})', args[2])
			self.assertIsNotNone(match)
			code = match.groups()[0]
			self.assertIsNotNone(db.getCode(code))

			# Clean up code
			db.DB_CONN.execute('DELETE FROM Codes WHERE code = ?', [code])
			db.DB_CONN.commit()

	def test_codesUnique(self):
		# Add a bunch of codes
		num_codes = 10
		added_codes = []
		for _ in range(num_codes):
			code = makeUniqueCode()
			db.addCode(code, self.test_id, 'test@email.com')
			added_codes.append(code)

		# Verify that all codes were added and unique
		cursor = db.DB_CONN.execute('''
				SELECT DISTINCT count(1)
				FROM Codes
				WHERE code IN ({})
			'''.format(','.join(['?'] * num_codes)),
			added_codes)
			# ^^^ Yes, python actually needs this jank^^^
		codes_added = cursor.fetchone()[0]
		self.assertEqual(codes_added, num_codes)

		# Cleanup
		db.DB_CONN.execute('''
				DELETE FROM Codes WHERE code IN ({})
			'''.format(','.join(['?'] * num_codes)),
			added_codes)


class ConfirmCodeTest(ServerTest):

	def setUp(self):
		super().setUp()
		self.test_id = db.addUser(self.test_user)
		self.test_code = 'Test1234'
		self.test_email = 'test@email.com'
		db.addCode(self.test_code, self.test_id, self.test_email)

	def tearDown(self):
		super().tearDown()
		db.DB_CONN.execute('DELETE FROM Codes WHERE code = ?', [self.test_code])

	def test_badCode(self):
		bad_codes = [
			'I am bad',
			'; 1 == 1',
			'code123<',
			'>code123',
			'short',
			'ThisIsTooLong'
		]
		for code in bad_codes:
			resp = self.app.get('/update/email/confirm/' + code)
			self.assertEqual(resp.status_code, 403)
			self.assertEqual(resp.get_data(as_text=True), 'Forbidden')

	def test_codeUsed(self):
		db.useCode(self.test_code)
		response = self.app.get('/update/email/confirm/' + self.test_code)

		self.assertEqual(response.status_code, 403)
		self.assertEqual(response.get_data(as_text=True), 'Forbidden')

		user = db.getUserById(self.test_id)
		self.assertIsNone(user.get('email', None))

	def test_deletedUser(self):
		db.DB_CONN.execute('DELETE FROM Users WHERE ID = ?', [self.test_id])
		response = self.app.get('/update/email/confirm/' + self.test_code)

		self.assertEqual(response.status_code, 403)
		self.assertEqual(response.get_data(as_text=True), 'Forbidden')

		user = db.getUserById(self.test_id)
		self.assertIsNone(user)

	def test_emailAdded(self):
		response = self.app.get('/update/email/confirm/' + self.test_code)

		self.assertEqual(response.status_code, 200)
		self.assertEqual(response.get_data(as_text=True), 'Ok')

		user = db.getUserById(self.test_id)
		self.assertEqual(user.get('email'), self.test_email)

		code = db.getCode(self.test_code)
		self.assertIsNone(code)


class GenericErrorTest(ServerTest):

	def test_badEndpoint(self):
		response = self.app.get('/bad/endpoint')
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

