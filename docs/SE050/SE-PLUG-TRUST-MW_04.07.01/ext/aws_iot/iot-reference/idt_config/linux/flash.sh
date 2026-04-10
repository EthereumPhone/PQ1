#!/bin/zsh

SOURCE_PATH=$1
IDE_PATH=<PATH TO IDE e.g. /usr/local/MCUXpressoIDE_x.y.z>
MCUX_WORKSPACE_LOC=$SOURCE_PATH
MCUX_FLASH_DIR0=<Path to IDE flash e.g. $IDE_PATH/ide/plugins/com.nxp.mcuxpresso.tools.bin.macosx_x.y.z/binaries/Flash>
MCUX_FLASH_DIR1=$SOURCE_PATH/.mcuxpressoide_packages_support/MIMXRT1062xxxxA_support/Flash
MCUX_IDE_BIN=<path to IDE BIN, e.g. $IDE_PATH/ide/plugins/com.nxp.mcuxpresso.tools.bin.macosx_x.y.z/binaries>
$MCUX_IDE_BIN/crt_emu_cm_redlink --flash-mass -p MIMXRT1062xxxxA --ConnectScript RT1060_connect.scp -ProbeHandle=1 -CoreIndex=0 --flash-driver LPC11_12_13_32K_8K.cfx -x $MCUX_WORKSPACE_LOC/projects/evkmimxrt1060/bootloader/Debug --flash-dir $MCUX_FLASH_DIR0 --flash-dir $MCUX_FLASH_DIR1 --flash-hashing
$MCUX_IDE_BIN/crt_emu_cm_redlink --flash-load-exec "$MCUX_WORKSPACE_LOC/projects/evkmimxrt1060/bootloader/Debug/bootloader.bin" -p MIMXRT1062xxxxA --load-base=0x60000000 --ConnectScript RT1060_connect.scp -ProbeHandle=1 -CoreIndex=0 --flash-driver= -x $MCUX_WORKSPACE_LOC/projects/evkmimxrt1060/bootloader/Debug --flash-dir $MCUX_FLASH_DIR0 --flash-dir $MCUX_FLASH_DIR1 --flash-hashing
$MCUX_IDE_BIN/crt_emu_cm_redlink --flash-load-exec "$MCUX_WORKSPACE_LOC/projects/evkmimxrt1060/test/Debug/aws_iot_qual_test_signed.bin" -p MIMXRT1062xxxxA --load-base=0x60040000 --ConnectScript RT1060_connect.scp -ProbeHandle=1 -CoreIndex=0 --flash-driver LPC11_12_13_32K_8K.cfx -x $MCUX_WORKSPACE_LOC/projects/evkmimxrt1060/test/Debug --flash-dir $MCUX_FLASH_DIR0 --flash-dir $MCUX_FLASH_DIR1 --flash-hashing