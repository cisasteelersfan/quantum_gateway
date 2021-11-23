from abc import ABC, abstractmethod
import hashlib
from http import HTTPStatus
from http.cookies import SimpleCookie
import json
import logging
from typing import Dict, List
import warnings
import weakref

import esprima
import requests
import urllib3

TIMEOUT = 5

_LOGGER = logging.getLogger(__name__)

def _encode_luci_string(unencoded_string):
    """Encodes a string to be sent to a G3100 gateway in a "luci_" POST parameter."""
    md5_hash = hashlib.md5(unencoded_string.encode('ascii')).hexdigest()
    return hashlib.sha512(md5_hash.encode('ascii')).hexdigest()


class Gateway(ABC):
    def __init__(self):
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


class Gateway3100(Gateway):
    def __init__(self, host, password):
        super().__init__()

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self.verify = False
        self.host = 'https://' + host
        self.username = 'admin'
        self.password = password
        self.token = ''

        self.session = requests.Session()

        # Attempt to log out when this object is destroyed.
        weakref.finalize(
            self,
            self.session.post,
            self.host + '/logout.cgi',
            timeout=TIMEOUT,
            verify=self.verify,
            data={'token': self.token},
        )

    @classmethod
    def _is_valid_host(cls, host):
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        return requests.get('https://' + host + '/loginStatus.cgi', verify=False).status_code != HTTPStatus.NOT_FOUND

    def get_connected_devices(self):
        res = self.session.get(
            self.host + '/cgi/cgi_owl.js', timeout=TIMEOUT, verify=self.verify
        )

        if res.status_code != HTTPStatus.OK:
            _LOGGER.warning('Failed to get connected devices from gateway; '
                            'got HTTP status code %s', res.status_code)

        connected_devices = {}

        # Unfortunately, the data is provided to the frontend not as a JSON
        # blob, but as some JavaScript to execute.  The below code uses a
        # JavaScript parser and AST visitor to extract the known device data
        # from the script.
        #
        # Example response:
        #
        # addROD('known_device_list', { 'known_devices': [ { 'mac': 'xx:xx:xx:xx:xx:xx', 'hostname': 'name' } ] });
        def visitor(node, metadata):
            if node.type != 'CallExpression':
                return

            if node.callee.type != 'Identifier' or node.callee.name != 'addROD':
                return

            if node.arguments[0].value != 'known_device_list':
                return

            known_devices_node = None
            for prop in node.arguments[1].properties:
                if prop.key.value == 'known_devices':
                    known_devices_node = prop.value

            if known_devices_node is None:
                _LOGGER.debug('Failed to find known_devices object in response data')
                return

            for device in known_devices_node.elements:
                data = {prop.key.value: prop.value.value for prop in device.properties}
                if 'activity' not in data or 'mac' not in data or 'hostname' not in data:
                    continue
                if data['activity'] == 1:
                    connected_devices[data['mac']] = data['hostname']

        lines = res.text.split("\n")
        for line in lines:
            if "known_device_list" in line:
                esprima.parseScript(line, {}, visitor)

        return connected_devices

    def _check_login_status(self):
        res = self.session.get(
            self.host + '/loginStatus.cgi', timeout=TIMEOUT, verify=self.verify
        )
        if res.status_code == HTTPStatus.OK and res.json()['islogin'] == '1':
            # Store the XSRF token for use in future requests.
            self.token = res.json()['token']
            return True
        return False

    def check_auth(self):
        if self._check_login_status():
            return True

        body = {
            'luci_username': _encode_luci_string(self.username),
            'luci_password': _encode_luci_string(self.password),
        }
        res = self.session.post(
            self.host + '/login.cgi', timeout=TIMEOUT, verify=self.verify, data=body
        )

        if res.status_code in (HTTPStatus.OK, HTTPStatus.FOUND):
            return self._check_login_status()

        if res.status_code == HTTPStatus.FORBIDDEN:
            response_json = res.json()
            if response_json.get('flag') == 2:
                _LOGGER.warning('Hit maximum session limit of %s sessions',
                                response_json['maxsession'])
        else:
            _LOGGER.debug('unexpected response code: %s', res.status_code)

        return False


class QuantumGatewayScanner:
    def __init__(self, host, password, use_https=True):
        self._gateway = self._get_gateway(host, password, use_https)
        self.success_init = self._gateway.check_auth()

    def _get_gateway(self, host, password, use_https) -> Gateway:
        if Gateway3100._is_valid_host(host):
            return Gateway3100(host, password)
        else:
            return Gateway1100(host, password, use_https)

    def scan_devices(self) -> List[str]:
        self.connected_devices = {}
        if self._gateway.check_auth():
            self.connected_devices = self._gateway.get_connected_devices()
        return self.connected_devices.keys()

    def get_device_name(self, device: str) -> str:
        return self.connected_devices.get(device)
