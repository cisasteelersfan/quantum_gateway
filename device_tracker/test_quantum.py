import unittest
import requests_mock
from quantum_gateway import Quantum

class TestQuantum(unittest.TestCase):
    # @requests_mock.mock()
    # def setUp(self, m):
    #     m.get('http://192.168.1.1/api/devices', status_code=200)

    # def tearDown(self):
    #     self.quantum.log_out()

    @requests_mock.mock()
    def testConstructor(self, m):
        m.get('http://192.168.1.2/api/devices', status_code=200)
        host = '192.168.1.2'
        password = 'wrong'
        self.quantum = Quantum(host, password)

        self.assertTrue(self.quantum.success_init)

if __name__ == '__main__':
    unittest.main()
