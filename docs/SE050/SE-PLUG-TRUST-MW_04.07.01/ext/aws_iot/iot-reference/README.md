## IoT Reference Integration on NXP i.MX RT1060 MCU and EdgeLock® SE050 Secure Element
### Introduction
The project demonstrates how to integrate FreeRTOS modular software libraries with the hardware capabilities of 
the [i.MX RT1060 Arm® Cortex®-M7 MCU](https://www.nxp.com/products/processors-and-microcontrollers/arm-microcontrollers/i-mx-rt-crossover-mcus/i-mx-rt1060-crossover-mcu-with-arm-cortex-m7-core:i.MX-RT1060) 
and the enhanced security features of the [Edgelock® SE050 secure element](https://www.nxp.com/products/security-and-authentication/authentication/edgelock-se050-plug-trust-secure-element-family-enhanced-iot-security-with-maximum-flexibility:SE050). 
The project contains reference implementations that show different IoT application tasks that run concurrently and securely communicate with AWS IoT. 
The implementation also shows how to perform over-the-air firmware updates that leverage the AWS IoT OTA service and secure bootloader capabilities from MCUBoot. 
The reference implementation runs on the [i.MX RT1060-EVKB evaluation board](https://www.nxp.com/design/development-boards/i-mx-evaluation-and-development-boards/i-mx-rt1060-evaluation-kit:MIMXRT1060-EVK) 
and [OM-SE050ARD secure element kit](https://www.nxp.com/products/security-and-authentication/authentication/edgelock-se050-development-kit:OM-SE050X).
For more details on the feature, see the [NXP Featured IoT Reference Integration](https://www.freertos.org/NXP-RT1060-SE050) page on [FreeRTOS.org](https://www.freertos.org/).
### Folder Structure
The folder inside the repository is organized as follows:
```
|— core/
|- Middleware/
   |- NXP/
   |- AWS/
   |- FreeRTOS/
   |- third_party libs
|- examples/
  |- evkbmimxrt1060/ 
  |- common/
|- projects/
   |- evkbmimxrt1060/ 
|- README.md
|- LICENSE
```
The root of the repository contains the following top level folders:
* `core` contains submodules to NXP's MCUX SDK repository. The repository hosts the MCUXpresso software development package which contains ARM CMSIS core files, 
  board support packages for devices, shared peripheral drivers and components.
* `Middleware` hosts NXP's middleware SDKs such as the Plug and Trust Middleware stack, the FreeRTOS Kernel and modular software libraries, AWS connectivity 
  libraries, and other third party libraries required for the project.
* `examples` hosts the IoT reference sample for the board. The common demo tasks, such as the MQTT Agent and OTA Agent, which are shared across different board 
  examples are placed under the `common` folder. The `evkbmimxrt1060` folder contains the demo samples for the board.
* `projects`  contains MCUXpresso IDE projects for the examples provided. Currently all projects are tested on the MCUXpresso IDE on a Windows platform.
### Demos
Source code in this repository includes the following demo projects:
* **bootloader**: an [MCUBoot](https://www.mcuboot.com/) bootloader ported to the i.MX RT1060 MCU. This is the second stage bootloader which performs application image signature verification 
  and encryption. 
  The key pair for MCUBoot signature verification is generated at the time the bootloader is prepared. The MCUBoot private key is stored securely on the customer's 
  premises and the public key for verification is embedded into the bootloader. The first stage bootloader uses an immutable ROM bootloader which is shipped with the i.MX RT1060 MCU. 
All other application projects are configured to flash the demo to an address known to the bootloader and require the bootloader to be pre-programmed prior to 
loading the application project. 
All demos include an over-the-air firmware update running in a background task, concurrently with other demo tasks, using the coreMQTT and coreMQTT-Agent libraries 
to manage the thread safety for the MQTT connection. See [coreMQTT](https://www.freertos.org/mqtt/index.html), [AWS IoT Over-the-air](https://www.freertos.org/ota/index.html) (OTA), [coreMQTT-Agent](https://www.freertos.org/mqtt-agent/index.html) for details.
* **aws_iot_pubsub**: a simple publish subscribe example. By default, there're 2 tasks concurrently sending incremental counters to cloud and listening to the data from cloud. These tasks are running concurrently with the over-the-air firmware update background task. 
* **aws_iot_shadow**: a simple shadow demo that updates the device’s powerOn state and runs concurrently with the over-the-air firmware update background task. See [AWS IoT Device Shadow](https://www.freertos.org/iot-device-shadow/index.html) for details.
* **aws_iot_defender**: a basic device defender demo that sends basic metrics about device health and runs concurrently with the over-the-air firmware update task. See [AWS IoT Device Defender](https://www.freertos.org/iot-device-defender/index.html) for details.
* **aws_iot_qual_test**: a test project set up executing tests against FreeRTOS integration and AWS IoT Core interoperability and best practices. See [FreeRTOS Libraries Integration Tests](https://github.com/FreeRTOS/Labs-FreeRTOS-Libraries-Integration-Tests) github repository, and [Device Advisor](https://docs.aws.amazon.com/iot/latest/developerguide/device-advisor.html) for details.
### Cloning the Repository
To clone using HTTPS:
```
git clone https://github.com/FreeRTOS/iot-reference-nxp-rt1060.git --recurse-submodules
```
Using SSH:
```
git clone git@github.com:FreeRTOS/iot-reference-nxp-rt1060.git --recurse-submodules
```
If you have downloaded the repo without using the `--recurse-submodules` argument, you should run:
```
git submodule update --init --recursive
```
### Running the demos
To get started running demos, see the [Getting Started Guide](GSG.md).
### Contributing
See [CONTRIBUTING](https://github.com/FreeRTOS/lab-iot-reference-nxp-rt1060/blob/main/CONTRIBUTING.md) for more information.
### License
The example source code under `./examples/` and the libraries under `./Middleware/AWS` and `./Middleware/FreeRTOS` are licensed under the MIT-0 License. See 
the `LICENSE` file. For all other source code licenses, including `core/` and `Middleware/NXP` folders, see the source header documentation.
