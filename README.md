# Query a Quantum Gateway

This library allows a Verizon FiOS Quantum Gateway to be queried. It uses the `requests` library to authenticate, log in, and query the web interface of the gateway.

## Usage

Please note for G1100 devices: as of the Firmware version 02.02.00.13 and UI version v1.0.388 https is the only way to get to the admin console. This is using a self signed cert as well. The code now defaults to https and ignores the self signed cert warning.

```python
# Import
from quantum_gateway import QuantumGatewayScanner

# Connect to gateway via HTTPS
gateway = QuantumGatewayScanner('192.168.1.1', 'your_password_here')

# Or, connect to gateway via HTTP
gateway = QuantumGatewayScanner('192.168.1.1', 'your_password_here', False)

# Property is set to True if we successfully logged in, otherwise False
gateway.success_init

# Get list of all connected devices' MAC addresses
gateway.scan_devices()

# Get specific device's name
gateway.get_device_name('mac address of device here')
```

## Notes

Tested on Verizon FiOS-provided gateway:

|                   |             |            |
| ----------------- | ----------- |------------|
| UI Version:       | v1.0.388    | Unknown    |
| Firmware Version: | 02.02.00.13 | 3.1.0.12   |
| Model Name:       | FiOS-G1100  | FiOS-G3100 |
| Hardware Version: | 1.03        | 1104       |

Please open a Github [issue](https://github.com/cisasteelersfan/quantum_gateway/issues) or reply to the Home Assistant forum [post](https://community.home-assistant.io/t/verizon-fios-quantum-gateway-device-tracker-platform/67944) if you encounter any problems. Thanks!
