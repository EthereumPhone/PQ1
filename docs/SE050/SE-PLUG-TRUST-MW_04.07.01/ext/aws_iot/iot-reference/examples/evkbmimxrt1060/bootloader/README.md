## MCUBoot Bootloader project

### Introduction

This example shows how to setup open source MCUboot bootloader, build and flash the bootloader project to MIMXRT1060-EVK board.


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


#### Create Signing keys for the bootloader

The project uses MCUBoot python script called `imgtool.py` to create signing keys, sign and verify the image locally.

1. Install necessary requirements for the image tool. From the repo root folder, execute:
```
pip3 install -r Middleware/mcuboot/scripts/requirements.txt
```
2. Create RSA bootloader signing credentials. Currently repository only supports RSA signature based valdidation. From root folder execute following commands:
```
python3 Middleware/mcuboot/scripts/imgtool.py keygen -k examples/evkbmimxrt1060/bootloader/signing_key.pem -t rsa-2048
python3 Middleware/mcuboot/scripts/imgtool.py getpub -k examples/evkbmimxrt1060/bootloader/signing_key.pem --lang c  > examples/evkbmimxrt1060/bootloader/signing_pub_key.c
```
You will need to use the `signing_key.pem` created above for signing the application image created during firmware update.

#### Building and Running the bootloader

1. Open MCUXpresso IDE and choose a workspace location in your file system.
2. From `File` menu choose `Open Projects from FileSytem` and then choose the project from folder `projects/evkmimxrt1060/bootloader`.
3. Build and flash the program through MCUXpresso IDE debugger.
4. Upon boot the bootloader checks for any image in the primary slot, if there is no image it simply waits in an infinite loop. Now you can go ahead and flash the application image to be booted. 
