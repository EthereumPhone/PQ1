
@REM Copyright 2019 NXP
@REM
@REM SPDX-License-Identifier: Apache-2.0
@REM

@echo on
adb root
adb wait-for-device
adb remount

adb push obj_arm/lib/libSSS_APIs.so 		/system/vendor/lib/libSSS_APIs.so
adb push obj_arm/lib/libmbedtls.so 		/system/vendor/lib/libmbedtls.so
adb push obj_arm/lib/liba7x_utils.so 	/system/vendor/lib/liba7x_utils.so

adb push obj/lib/libSSS_APIs.so 	/system/vendor/lib64/libSSS_APIs.so
adb push obj/lib/libmbedtls.so 	/system/vendor/lib64/libmbedtls.so
adb push obj/lib/liba7x_utils.so 	/system/vendor/lib64/liba7x_utils.so

adb push obj_arm/lib/libsoftkeymasterdevice.so 	/system/lib/libsoftkeymasterdevice.so
adb push obj/lib/libsoftkeymasterdevice.so 	/system/lib64/libsoftkeymasterdevice.so

adb push obj_arm/lib/libse050keymasterdevice.so 	/system/lib/libse050keymasterdevice.so
adb push obj/lib/libse050keymasterdevice.so 	/system/lib64/libse050keymasterdevice.so

adb push obj_arm/lib/libsoftkeymaster.so 	/system/lib/libsoftkeymaster.so
adb push obj/lib/libsoftkeymaster.so 	/system/lib64/libsoftkeymaster.so

adb push obj_arm/lib/libkeymaster1.so 	/system/lib/libkeymaster1.so
adb push obj/lib/libkeymaster1.so 	/system/lib64/libkeymaster1.so

adb push vendor/lib64/hw/android.hardware.keymaster@3.0-impl.so 						/system/vendor/lib64/hw/android.hardware.keymaster@3.0-impl.so
adb push vendor/lib/hw/android.hardware.keymaster@3.0-impl.so 							/system/vendor/lib/hw/android.hardware.keymaster@3.0-impl.so
adb push vendor/bin/hw/android.hardware.keymaster@3.0-service 							/system/vendor/bin/hw/android.hardware.keymaster@3.0-service
adb push testcases/VtsHalKeymasterV3_0TargetTest/arm/VtsHalKeymasterV3_0TargetTest 		/system/vendor/bin/VtsHalKeymasterV3_0TargetTest
adb push testcases/se050keymaster_tests/arm64/se050keymaster_tests                        /system/vendor/bin/se050keymaster_tests

pause
adb reboot
pause
