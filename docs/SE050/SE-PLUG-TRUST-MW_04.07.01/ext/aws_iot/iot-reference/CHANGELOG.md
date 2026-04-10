# Changelog for NXP i.MX RT1060 Featured FreeRTOS IoT Integration

## v202212.00 ( December 2022 )
- [#33](https://github.com/FreeRTOS/iot-reference-nxp-rt1060/pull/33) and [#29](https://github.com/FreeRTOS/iot-reference-nxp-rt1060/pull/29) Update Long Term Support (LTS) libraries to 202210.01-LTS:
  * [FreeRTOS-Kernel V10.5.1](https://github.com/FreeRTOS/FreeRTOS-Kernel/blob/V10.5.1/History.txt)
  * [coreMQTT v2.1.1](https://github.com/FreeRTOS/coreMQTT/blob/v2.1.1/CHANGELOG.md)
  * [corePKCS11 v3.5.0](https://github.com/FreeRTOS/corePKCS11/tree/v3.5.0)
  * [coreJSON v3.2.0](https://github.com/FreeRTOS/coreJSON/tree/v3.2.0)
  * [backoffAlgorithm v1.3.0](https://github.com/FreeRTOS/backoffAlgorithm/tree/v1.3.0)
  * [AWS IoT Device Shadow v1.3.0](https://github.com/aws/Device-Shadow-for-AWS-IoT-embedded-sdk/tree/v1.3.0)
  * [AWS IoT Device Defender v1.3.0](https://github.com/aws/Device-Defender-for-AWS-IoT-embedded-sdk/tree/v1.3.0)
  * [AWS IoT Over-the-air Update v3.4.0](https://github.com/aws/ota-for-aws-iot-embedded-sdk/tree/v3.4.0)

- [#28](https://github.com/FreeRTOS/iot-reference-nxp-rt1060/pull/28) Add IDT configs for passing qualification suite 
- [#27](https://github.com/FreeRTOS/iot-reference-nxp-rt1060/pull/27) demos: Make alpn identifiers work with mbedtls 
- [#26](https://github.com/FreeRTOS/iot-reference-nxp-rt1060/pull/26) Set default configuration to retry connection forever 
- [#21](https://github.com/FreeRTOS/iot-reference-nxp-rt1060/pull/21) Update FreeRTOS Kernel to V10.4.3-LTS-Patch-2 
- [#19](https://github.com/FreeRTOS/iot-reference-nxp-rt1060/pull/19) and [#20](https://github.com/FreeRTOS/iot-reference-nxp-rt1060/pull/20) Change MQTT PUB/SUB retry behavior and minor refactor
- [#18](https://github.com/FreeRTOS/iot-reference-nxp-rt1060/pull/18) Add default error messages for generating bootloader keys
- [#16](https://github.com/FreeRTOS/iot-reference-nxp-rt1060/pull/16) Device advisor integration
- [#14](https://github.com/FreeRTOS/iot-reference-nxp-rt1060/pull/14) Update ci.yml to ignore NXP directory
- [#12](https://github.com/FreeRTOS/iot-reference-nxp-rt1060/pull/12) Support for OTA E2E test
- [#10](https://github.com/FreeRTOS/iot-reference-nxp-rt1060/pull/10) Updated the test project for OTA and PKCS11 test
- [#9](https://github.com/FreeRTOS/iot-reference-nxp-rt1060/pull/9) Updated test project to run qualification tests
- [#8](https://github.com/FreeRTOS/iot-reference-nxp-rt1060/pull/8), [#11](https://github.com/FreeRTOS/iot-reference-nxp-rt1060/pull/11), [#15](https://github.com/FreeRTOS/iot-reference-nxp-rt1060/pull/15), [#17](https://github.com/FreeRTOS/iot-reference-nxp-rt1060/pull/17), [#22](https://github.com/FreeRTOS/iot-reference-nxp-rt1060/pull/22), [#23](https://github.com/FreeRTOS/iot-reference-nxp-rt1060/pull/23), [#24](https://github.com/FreeRTOS/iot-reference-nxp-rt1060/pull/24), [#25](https://github.com/FreeRTOS/iot-reference-nxp-rt1060/pull/25) and [#34](https://github.com/FreeRTOS/iot-reference-nxp-rt1060/pull/34)  Manifest, project file and documentation updates
  
## v202203.00 ( March 2022 )

This is the first release for the repository.

The repository contains IoT Reference integration projects using NXP i.MX RT1060 MCU and Edgelock® SE050 Secure element. This release includes the following examples:
* MCUBoot second-stage bootloader
* MQTT Publish/Subscribe with OTA capability
* Device Shadow with OTA capability
* Device Defender with OTA capability
