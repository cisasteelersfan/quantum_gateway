from abc import ABC, abstractmethod
import hashlib
from http.cookies import SimpleCookie
import json
from typing import Dict, List

import requests
import urllib3

TIMEOUT = 5


class Gateway(ABC):
    def __init__(self) -> None:
        super().__init__()

        self.connected_devices = {}
        self.success_init = False

    @abstractmethod
    def check_auth(self) -> bool:
        """Attempts to authenticate with the device.
        
        Returns whether or not authentication succeeded.
        """
        return NotImplementedError()

    @abstractmethod
    def get_connected_devices(self) -> Dict[str, str]:
        """Gets the connected devices as a MAC address -> hostname map."""
        return NotImplementedError()


class Gateway1100(Gateway):
    def __init__(self, host, password, use_https=True):
        super().__init__()

        self.verify = False
        
        if use_https:
            self.scheme = 'https'
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        else:
            self.scheme = 'http'

        self.host = self.scheme + '://' + host
        self.password = password

        self.session = requests.Session()

    def get_connected_devices(self):
        devices_raw = self.session.get(self.host + '/api/devices', timeout=TIMEOUT, verify=self.verify)
        devices = json.loads(devices_raw.text)
        return {device['mac']: device['name'] for device in devices if device['status']}

    def check_auth(self):
        res = self.session.get(self.host + '/api/devices', timeout=TIMEOUT, verify=self.verify)
        if res.status_code == 200:
            return True

        getLogin = self.session.get(self.host + '/api/login', timeout=TIMEOUT, verify=self.verify)
        salt = getLogin.json()['passwordSalt']

        encodedPassword = hashlib.sha512()
        encodedPassword.update((self.password + salt).encode('ascii'))

        payload = json.dumps({"password": encodedPassword.hexdigest()})

        postLogin = self.session.post(self.host + '/api/login', data=payload, timeout=TIMEOUT, verify=self.verify)
        token = SimpleCookie(postLogin.headers.get('set-cookie'))['XSRF-TOKEN'].value

        self.session.headers.update({'X-XSRF-TOKEN': token})

        res = self.session.get(self.host + '/api/devices', timeout=TIMEOUT, verify=self.verify)
        if res.status_code == 200:
            return True
        return False


class QuantumGatewayScanner:
    def __init__(self, host, password, use_https=True):
        self._gateway = self._get_gateway(host, password, use_https)
        self.success_init = self._gateway.check_auth()

    def _get_gateway(self, host, password, use_https) -> Gateway:
        return Gateway1100(host, password, use_https)

    def scan_devices(self) -> List[str]:
        self.connected_devices = {}
        if self._gateway.check_auth():
            self.connected_devices = self._gateway.get_connected_devices()
        return self.connected_devices.keys()

    def get_device_name(self, device: str) -> str:
        return self.connected_devices.get(device)