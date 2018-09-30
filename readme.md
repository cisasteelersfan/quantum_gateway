# Query a Quantum Gateway

This library allows a Verizon FiOS Quantum Gateway to be queried. It uses the `requests` library to authenticate, log in, and query the web interface of the gateway.

## Usage

```python
from quantum_gateway import QuantumGatewayScanner

# Connect to gateway
gateway = QuantumGatewayScanner('192.168.1.1', 'your_password_here')

# Ensure successful connection
gateway.success_init

# Get list of all connected devices' MAC addresses
gateway.scan_devices()

# Get specific device's name
gateway.get_device_name('mac address of device here')
```

## Thoughts

I have only tested on my own Verizon FiOS-provided gateway:

|  |  |
| --- | --- |
| UI Version:  | v1.0.294 |
| Firmware Version: | 02.00.01.08 |
| Model Name: | FiOS-G1100 |
| Hardware Version: | 1.03 |

Please open a Github [issue](https://github.com/cisasteelersfan/quantum_gateway/issues) or reply to the Home Assistant forum [post](https://community.home-assistant.io/t/verizon-fios-quantum-gateway-device-tracker-platform/67944) if you encounter any problems. Thanks!
