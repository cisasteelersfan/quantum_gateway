import unittest
import json
import hashlib
import requests_mock
import re
from quantum_gateway import Quantum

@requests_mock.Mocker()
class TestQuantum(unittest.TestCase):
    DEVICES_MATCHER = re.compile('^.*/api/devices$')
    LOGIN_MATCHER = re.compile('^.*/api/login$')
    TOKEN = 'TEST_TOKEN'
    PASSWORD_SALT = 'TEST_SALT'
    CORRECT_PASSWORD = 'correct'
    WRONG_PASSWORD = 'wrong'
    CONNECTED_DEVICES = {'00:11:22:33:44:55': 'iphone', '00:00:00:00:00:00': 'computer'}
    SERVER_CONNECTED_DEVICES_RESPONSE = '[{"mac": "00:11:22:33:44:55", "name": "iphone", "status": true}, {"mac": "00:00:00:00:00:00", "name": "computer", "status": true}, {"mac": "11:11:11:11:11:11", "name": "disconnected", "status": false}]'

    logged_in = False

    def setUp(self):
        self.logged_in = False

    def test_login_success(self, m):
        self.setup_matcher(m)

        host = '192.168.1.2'
        password = self.CORRECT_PASSWORD
        quantum = Quantum(host, password)

        self.assertTrue(quantum.success_init)

    def test_login_fail(self, m):
        self.setup_matcher(m)

        host = '192.100.100.5'
        password = self.WRONG_PASSWORD
        quantum = Quantum(host, password)

        self.assertFalse(quantum.success_init)

    def test_scan_devices(self, m):
        self.setup_matcher(m)

        host = 'mywifigateway.com'
        password = self.CORRECT_PASSWORD

        quantum = Quantum(host, password)

        devices = quantum.scan_devices()

        self.assertEqual(devices, self.CONNECTED_DEVICES.keys())

    def test_get_device_name(self, m):
        self.setup_matcher(m)

        host = '10.0.0.1'
        password = self.CORRECT_PASSWORD

        quantum = Quantum(host, password)

        quantum.scan_devices()

        self.assertEqual(self.CONNECTED_DEVICES.get('00:00:00:00:00:00'), quantum.get_device_name('00:00:00:00:00:00'))


    def setup_matcher(self, m):
        def devices_callback(request, context):
            if self.is_logged_in(request):
                context.status_code = 200
                return self.SERVER_CONNECTED_DEVICES_RESPONSE
            else:
                context.status_code = 401

        def password_callback(request, context):
            if self.is_correct_password(request):
                context.status_code = 200
                self.logged_in = True
            else:
                context.status_code = 401
            context.headers['set-cookie'] = 'XSRF-TOKEN=' + self.TOKEN

        m.get(self.DEVICES_MATCHER, text=devices_callback)
        m.get(self.LOGIN_MATCHER, status_code=200, json={'passwordSalt': self.PASSWORD_SALT})
        m.post(self.LOGIN_MATCHER, text=password_callback)

    def is_logged_in(self, request):
        return self.logged_in and request.headers.get('X-XSRF-TOKEN') == self.TOKEN

    def is_correct_password(self, request):
        hash = hashlib.sha512()
        hash.update((self.CORRECT_PASSWORD + self.PASSWORD_SALT).encode('ascii'))
        expected_encoded_password = hash.hexdigest()
        actual_encoded_password = json.loads(request.body)['password']

        return actual_encoded_password == expected_encoded_password

if __name__ == '__main__':
    unittest.main()
