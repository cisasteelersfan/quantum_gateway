import logging

import hashlib
from http.cookies import SimpleCookie
import json
import requests
import voluptuous as vol
from .Quantum import Quantum

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
        self.host = config[CONF_HOST]
        self.password = config[CONF_PASSWORD]
        _LOGGER.info("Initializing")

        self.quantum = Quantum(self.host, self.password)

        self.success_init = self.quantum.success_init

    def scan_devices(self):
        return self.quantum.scan_devices()

    def get_device_name(self, device):
        return self.quantum.get_device_name(device)
