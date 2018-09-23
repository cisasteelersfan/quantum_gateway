import logging

import hashlib
from http.cookies import SimpleCookie
import json
import requests
import voluptuous as vol

from homeassistant.components.device_tracker import (DOMAIN, PLATFORM_SCHEMA,
                                                     DeviceScanner)
from homeassistant.const import (CONF_HOST, CONF_PASSWORD)
import homeassistant.helpers.config_validation as cv

_LOGGER = logging.getLogger(__name__)

DEFAULT_HOST = 'myfiosgateway.com'

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Optional(CONF_HOST, default=DEFAULT_HOST): cv.string
})


def get_scanner(hass, config):
    scanner = QuantumGatewayDeviceScanner(config[DOMAIN])

    return scanner if scanner.success_init else None


class QuantumGatewayDeviceScanner(DeviceScanner):

    def __init__(self, config):
        self.host = 'http://' + config[CONF_HOST]
        self.password = config[CONF_PASSWORD]

        self.last_results = []

        _LOGGER.info("Initializing")

        self._update_info()

        self.success_init = True

    def scan_devices(self):
        self._update_info()

        macs = [device['mac'] for device in self.last_results]

        return macs

    def get_device_name(self, device):
        try:
            return next(entry['name'] for entry in self.last_results
                        if entry['mac'] == device)
        except StopIteration:
            return None

    def _update_info(self):
        self.last_results = []

        with requests.Session() as session:
            getLogin = session.get(self.host + '/api/login')
            salt = getLogin.json()['passwordSalt']

            encodedPassword = hashlib.sha512()
            encodedPassword.update((self.password + salt).encode('ascii'))

            payload = json.dumps({"password": encodedPassword.hexdigest()})

            postLogin = session.post(self.host + '/api/login', data=payload)
            token = SimpleCookie(postLogin.headers.get('set-cookie'))['XSRF-TOKEN'].value

            session.headers.update({'X-XSRF-TOKEN': token})

            devicesRes = session.get(self.host + '/api/devices')
            devices = json.loads(devicesRes.text)

            session.get(self.host + '/api/logout')

            self.last_results = [{'mac': device['mac'], 'name': device['name']} for device in devices if device['status']]

class Quantum():
    def __init__(self, host, password):
        self.host = 'http://' + host
        self.password = password

        self.session = requests.Session()

        self.success_init = self._check_auth()

    def scan_devices(self):
        pass
    def get_device_name(self, device):
        pass

    def _check_auth(self):
        res = self.session.get(self.host + '/api/devices')
        if res.status_code == 200:
            return True

        getLogin = self.session.get(self.host + '/api/login')
        salt = getLogin.json()['passwordSalt']

        encodedPassword = hashlib.sha512()
        encodedPassword.update((self.password + salt).encode('ascii'))

        payload = json.dumps({"password": encodedPassword.hexdigest()})

        postLogin = self.session.post(self.host + '/api/login', data=payload)
        token = SimpleCookie(postLogin.headers.get('set-cookie'))['XSRF-TOKEN'].value

        self.session.headers.update({'X-XSRF-TOKEN': token})

        res = self.session.get(self.host + '/api/devices')
        if res.status_code == 200:
            return True
        return False

    def log_out(self):
        self.session.get(self.host + '/api/logout')
