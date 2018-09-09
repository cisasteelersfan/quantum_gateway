# Quantum Gateway device_scanner for Home Assistant
This platform adds support for the Verizon FiOS Quantum Gateway to Home Assistant's presence detection.

This is a work in progress. The end goal is to create a PyPI package and submit a proper pull request to [Home Assistant](https://github.com/home-assistant/home-assistant).

## Instructions
* Clone or unzip into your custom_components directory. (ie, should have `<config_directory, typically .homeassistant>/custom_components/device_tracker/quantum_gateway.py`)
* Add to your configuration.yaml:
```
device_tracker:
  - platform: quantum_gateway
    host: 192.168.1.1
    password: yourPasswordHere
```

  Note that providing the `host` is optional. By default, it uses `myfiosgateway.com`. Your password is often found printed on the router.

  My router does not allow me to change the username from `admin` so I did not include it as a parameter.

## Thoughts
I have only tested on my own Verizon FiOS-provided gateway:

|  |  |
| --- | --- |
| UI Version:  | v1.0.294 |
| Firmware Version: | 02.00.01.08 |
| Model Name: | FiOS-G1100 |
| Hardware Version: | 1.03 |

Please open a Github issue or reply to the [forum post](https://community.home-assistant.io/t/verizon-fios-quantum-gateway-device-tracker-platform/67944) if you encounter any problems. Thanks!

![Example FiOS Gateway](https://cdn.arstechnica.net/wp-content/uploads/2016/07/fios-quantum-gateway.png)
