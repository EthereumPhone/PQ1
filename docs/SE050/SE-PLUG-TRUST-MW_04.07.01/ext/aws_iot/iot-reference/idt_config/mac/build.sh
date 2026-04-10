#!/bin/zsh
SOURCE_PATH=$1
IDE_PATH=<PATH TO IDE e.g. /Applications/MCUXpressoIDE_x.y.z>
TOOLCHAIN_PATH=$IDE_PATH/ide/tools/bin
IDE=$IDE_PATH/ide/MCUXpressoIDE.app/Contents/MacOS/mcuxpressoide
rm -r $SOURCE_PATH/.metadata
$IDE -nosplash -application org.eclipse.cdt.managedbuilder.core.headlessbuild -data $SOURCE_PATH -verbose -import "$SOURCE_PATH/projects/evkmimxrt1060/bootloader" -build bootloader/Debug && \
$IDE -nosplash -application org.eclipse.cdt.managedbuilder.core.headlessbuild -data $SOURCE_PATH -verbose -import "$SOURCE_PATH/projects/evkmimxrt1060/test" -build aws_iot_qual_test/Debug && \
python3 "$SOURCE_PATH/Middleware/mcuboot/scripts/imgtool.py" sign -k $SOURCE_PATH/examples/evkbmimxrt1060/bootloader/signing_key.pem --align 4  --header-size 0x400 --pad-header --slot-size 0x200000 --max-sectors 800 --version "1.0" --pad --confirm $SOURCE_PATH/projects/evkmimxrt1060/test/Debug/aws_iot_qual_test.bin $SOURCE_PATH/projects/evkmimxrt1060/test/Debug/aws_iot_qual_test_signed.bin && \
python3 "$SOURCE_PATH/Middleware/mcuboot/scripts/imgtool.py" sign -k $SOURCE_PATH/examples/evkbmimxrt1060/bootloader/signing_key.pem --align 4  --header-size 0x400 --pad-header --slot-size 0x200000 --max-sectors 800 --version "1.0" $SOURCE_PATH/projects/evkmimxrt1060/test/Debug/aws_iot_qual_test.bin $SOURCE_PATH/projects/evkmimxrt1060/test/Debug/aws_iot_qual_test_signed_OTA.bin
