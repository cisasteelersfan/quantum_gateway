import unittest
import requests_mock
import re
from quantum_gateway import Quantum

@requests_mock.Mocker()
class TestQuantum(unittest.TestCase):
    DEVICES_MATCHER = re.compile('^.*/devices$')
    LOGIN_MATCHER = re.compile('^.*/login$')
    TOKEN = 'TEST_TOKEN'
    PASSWORD_SALT = 'TEST_SALT'

    def test_login_success(self, m):
        self.setup_matcher(m)
        
        host = '192.168.1.2'
        password = 'wrong'
        self.quantum = Quantum(host, password)

        self.assertTrue(self.quantum.success_init)

    def setup_matcher(self, m):
        def devices_callback(request, context):
            if request.headers.get('X-XSRF-TOKEN') == self.TOKEN:
                context.status_code = 200
            else:
                context.status_code = 401

        m.get(self.DEVICES_MATCHER, text=devices_callback)
        m.get(self.LOGIN_MATCHER, status_code=200, json={'passwordSalt': self.PASSWORD_SALT})
        def password_callback(request, context):
            context.status_code = 200
            context.headers['set-cookie'] = 'XSRF-TOKEN=' + self.TOKEN
        m.post(self.LOGIN_MATCHER, text=password_callback)

if __name__ == '__main__':
    unittest.main()
