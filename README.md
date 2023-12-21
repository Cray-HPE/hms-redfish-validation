# Redfish Validation Driver

## Description

Validation of Redfish BMCs uses several tools written in python. This driver
encapsulates those tools into containers and executes them against the target
hardware.

Tools:
    Redfish Interop Validation from DMTF
    Redfish Stress Test from HPE
    Redfish Valdiation Tools from HPE
    
### Prerequisites

- Container environment available
- podman-compose
- python3
- Power capping is enabled on the device, if applicable

### Installation

If the system this tool is going to execute from requires a proxy to access the
internet, the following steps require the proxy settings to be in place.

1. Create and activate python3 virtual environment.
   ```
   python3 -m venv validate
   cd validate
   . bin/activate
   ```

2. Clone repository
    ```
    git clone git@github.com:Cray-HPE/hms-redfish-validation.git
    ```
    or
    ```
    git clone https://github.com/Cray-HPE/hms-redfish-validation.git
    ```

3. Configure submodules and install requirements
   ```
   cd hms-redfish-validation
   git submodule update --init
   pip install -r requirements.txt
   ```

### Builing the containers when using a proxy

If the system the validator.py script is going to be running from requires a
proxy to access the internet, the containers needs to be built with the proxy
settings in place.

```
podman-compose build
```

### Usage

#### Viewing available tests
```
# ./validate.py -l
Redfish Validation driver

Available tests:
	rfvalidate     	required options:   defaults: 
	sustained      	required options:   defaults: 
	peak           	required options: --hosts [hostlist]  defaults: none
	walk           	required options:   defaults: 
	power-cap      	required options:   defaults: 
	power-control  	required options:   defaults: 
	telemetry      	required options:   defaults: 

Available profiles:
	CSMRedfishProfile-GPU.v1_0_0
	CSMRedfishProfile.test
	CSMRedfishProfile.v1_0_0
	CSMRedfishProfile.v1_1_0
	CSMRedfishProfile.v1_2_0
	CSMRedfishProfile.v1_3_0
```

## Compatibility

_List the versions of the project and their associated dependencies and any other compatibility information. A table is often the easiest way to communicate compatibility information. The [Kubernetes python client](https://github.com/kubernetes-client/python#compatibility) is a good example._

## Support

_Tell people where they can go to for help. It can be any combination of an issue tracker, a chat room, an email address, official documentation, etc._

* [Slack Channel(s)]
* [Admin or installation guide section]
* [CSM SIG group discussions in Cray-HPE/community repository]

## Roadmap (optional)

_If you have ideas for releases in the future, it is a good idea to provide links to the roadmap, wherever they reside (CASMFEAT-###)._

## Contributing

See the [CONTRIBUTING.md](CONTRIBUTING.md) file for how to contribute to this project.

## Changelog

See the [CHANGELOG.md](CHANGELOG.md) for the changes and release history of this project.

## Authors and Acknowledgments (optional)

_Show your appreciation to those who have contributed to the project._

## License

This project is copyrighted by Hewlett Packard Enterprise Development LP and is distributed under the MIT license. See the [LICENSE.txt](LICENSE.txt) file for details.
