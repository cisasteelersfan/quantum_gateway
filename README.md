# Query a Quantum Gateway

This library allows a Verizon FiOS Quantum Gateway to be queried. It uses the `requests` library to authenticate, log in, and query the web interface of the gateway.

## Usage

Please note as of the Firmware version 02.02.00.13 and UI version v1.0.388 https is the only way to get to the admin console. This is using a self signed cert as well. This code now defaults to https and ignores the self signed cert warning. 

from quantum_gateway import QuantumGatewayScanner

# Connect to gateway via HTTP
```python
gateway = QuantumGatewayScanner('192.168.1.1', 'your_password_here')
``` 

# Connect to gateway via HTTP
```python 
gateway = QuantumGatewayScanner('192.168.1.1', 'your_password_here',False)
``` 

# Ensure successful connection
```python
gateway.success_init
```
# Get list of all connected devices' MAC addresses
```python
gateway.scan_devices()
```
# Get specific device's name
```python
gateway.get_device_name('mac address of device here')
```



## Notes

Tested on Verizon FiOS-provided gateway:

|  |  |
| --- | --- |
| UI Version:  |  v1.0.388 |
| Firmware Version: |  02.02.00.13 |
| Model Name: | FiOS-G1100 |
| Hardware Version: | 1.03 |

Please open a Github [issue](https://github.com/cisasteelersfan/quantum_gateway/issues) or reply to the Home Assistant forum [post](https://community.home-assistant.io/t/verizon-fios-quantum-gateway-device-tracker-platform/67944) if you encounter any problems. Thanks!

