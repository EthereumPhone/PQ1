## MQTT Publish Subscribe Demo

### Introduction
This example demonstrates multiple MQTT publish subscribe task running concurrently with Over-The-Air firmware update background task, using coreMQTT agent libary to manage the thread safety for the MQTT connection.Each publish subscribe task runs in a loop to publish a message to AWS IoT MQTT broker on a topic, and receive same message back by subscribing to the publish topic. Topics are constructed per device and per task for this demo. You can  view the number of messages published by each task by logging to AWS IoT console and subscribing to respective topics.
OTA firmware update task runs OTA Agent loop which polls for and subscribes to OTA job requests from AWS IoT OTA service. The OTA agent task receives firmware chunks and sends control packets over MQTT, concurrently using coreMQTT agent task for thread safety.

### Hardware requirements

- Mini/micro USB cable
- MIMXRT1060-EVKB board
- OM-SE050ARD Development kit
- Personal Computer with Windows platform
- Network cable RJ45 standard (Network with Internet access)

### Toolchain Requirements

- MCUXpresso IDE
- python3 and pip
- openssl

### Board Setup

1. Plug in the OM-SE050ARD development kit to arduino headers on the MIMXRT1060-EVKB board.
3. Connect the USB cable between the personal computer and open SDA USB port (J1) on the board.
2. Connect the RJ45 cable to the ethernet port.

### Preparing the demo

#### Setting up the bootloader project

The demo contains firmware over the air updates functionality for which the secure bootloader is required. To setup, build and flash bootloader project see the [README](https://github.com/FreeRTOS/lab-iot-reference-nxp-rt1060/tree/main/examples/evkbmimxrt1060/bootloader/README.md).

#### Setting up the demo project

1. Open the MCUXpresso IDE and choose a workspace location in your filesystem. 
2. Click on `File` then `Open Projects from the FileSystem`. Choose the project from folder `projects/evkmimxrt1060/pubsub`. Import the project into the workspace.
3. Build and flash the demo from the IDE.
4. The project is configured to flash the demo to an address known to the bootloader. To boot a new application image from IDE, we have to jump start the application from the debugger. To do so:
   a. Launch the application as normal from the debugger IDE. The debugger goes into an endless loop after flashing the image.
   b. Pause the debugger. Go to `Debugger Console` in the bottom pane and type `jump ResetISR` to jump to application starting address. From then, application   execution can be continued normally.

### Provisioning the board

The project requires a one time setup of MQTT broker endpoint and device credentials required for connecting to AWS IoT core, and also the thing name by which the device is registered with AWS IoT.

1. By default the project boots into a provision mode at startup where all the configuration can be setup. The provisioning mode can be controlled using the flag `appmainPROVISIONING_MODE` in `examples/evkbmimxrt1060/pubsub/app_main.c`.
2. The provisioning mode waits for user input commands from a CLI task. 
3. Connect to the USB port using a serial terminal of the choice.
4. Run the following command to get the  pre-provisioned X.509 certificate from secure element:
```
pki get cert sss:F0000001
```
`sss:F0000001` is the slot where the certificate is stored in secure element.

5. Copy the PEM certificate from console and register the certificate with AWS IoT without a CA using doc [here](https://docs.aws.amazon.com/iot/latest/developerguide/manual-cert-registration.html#manual-cert-registration-console-noca).

6. Get the AWS IoT MQTT broker endpoint from `Settings` tab in AWS IoT console. Provision the endpoint by executing the following command:
```
conf set mqtt_endpoint <endpoint>
```
7. Create a new thing, device policy in AWS as mentioned in the doc [here](https://docs.aws.amazon.com/iot/latest/developerguide/create-iot-resources.html). Attach the certificate registered in step 5 with the thing name. Provision the new thing name to the device:
```
conf set thing_name <thing name>
```
8. Once the configurations are setup turn off the provisioning mode by setting `appmainPROVISIONING_MODE` to `0` and then recompiling and flashing the image onto the board.

### Runnning the publish subscribe demo

The board should be successfully provisioned at this time. Provisioning mode should be turned off by seting `appmainPROVISIONING_MODE` to `0` in `examples/evkbmimxrt1060/pubsub/app_main.c`.  Demo on startup, establishes a TLS connection with AWS IoT MQTT broker and runs the publish subscribe demo tasks using coreMQTT agent. By default two pubsub task are created. You can adjust the number of tasks created by setting the config `appmainMQTT_NUM_PUBSUB_TASKS` in `examples/evkbmimxrt1060/pubsub/app_main.c` to respective value.

### Perform Firmware Over-The-Air Updates with AWS IoT

The demo leverages OTA client library and AWS IoT OTA service for code signing and secure download of firmware updates. Safe and secure boot process along with root of trust verification is performed using opensource MCUBoot secondary bootloader. As a pre-requisite you should have built and flash the bootloader project from this repository.

#### Setup
This is a one time setup required for performing OTA firmware updates.

1. Setup AWS IoT OTA service resources as mentioned in pre-requisites doc [here](https://docs.aws.amazon.com/freertos/latest/userguide/ota-prereqs.html).
2. Create ECDSA credentials to perform code signing verification by the OTA library. You can refer to the doc [here](https://docs.aws.amazon.com/freertos/latest/userguide/ota-code-sign-cert-win.html) on how to create the credentials and register a new code signing profile in your AWS account.
3.  Provision the code signining public key to the board using the steps below.
      1. Get the ECDSA public key from the code signing credentials generated in step 2:
      ```
      openssl ec -in ecdsasigner.key -pubout -outform PEM -out ecdsasigner-pub-key.pem
      ```
      2. Switch to device provisioning mode by setting `appmainPROVISIONING_MODE` to `1`, recompiling and downloading the firmware.
      3. On the terminal CLI prompt, run the following command:
      ```
      pki set pub_key sss:00223344
      ```
     4. CLI waits to input the public key. Copy the PEM public key created in above step and paste it to serial terminal. Press `Enter`.
     5. On successful provisioning, the CLI should print `OK`. At this point you can switch back to device normal mode by turning off `appmainPROVISIONING_MODE` flag.

#### Creating a new firmware update job

1. Go to `examples/common/ota/ota_update.c` and increment the version number `APP_VERSION_MAJOR` for the new image.
2. Build the new image.
3. Sign the new binary image using MCUBoot key-pair generated as part of setting up the bootloader project. From the repository root folder execute following command:
```
python3 Middleware/mcuboot/scripts/imgtool.py sign -k examples/evkbmimxrt1060/bootloader/keys/<signing key generated in bootloader project> --align 4  --header-size 0x400 --pad-header --slot-size 0x200000 --max-sectors 800 --version "1.0" projects/evkmimxrt1060/pubsub/Debug/aws_iot_pubsub.bin aws_iot_pubsub_signed.bin
```
This should create a new signed MCUboot image named `aws_iot_pubsub_signed.bin`

4. Create a firmware update job using the signed image following the steps [here](https://docs.aws.amazon.com/freertos/latest/userguide/ota-console-workflow.html).
5. Once the job is create successfully, the demo should start downloading the firmware chunks. The process can be monitored using logs from the console. 

#### Verification and Bootup of new Image
Once all the firmware image chunks are downloaded and the signature is validated, the demo resets by itself. MCUBoot loader verifies the new image using the signing public key created as part of bootloader project. Once the image is verified, the bootloader swaps the image and boots up the new image. The new image on booting up verifies the image version with AWS IoT and marks the job as completed successfully. 
