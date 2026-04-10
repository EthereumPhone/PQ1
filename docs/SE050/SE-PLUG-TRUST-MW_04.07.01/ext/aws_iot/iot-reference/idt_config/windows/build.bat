SET IDE_PATH=<PATH TO IDE e.g. C:\nxp\MCUXpressoIDE_x.y.z>
SET SOURCE_PATH=%1%
SET TOOLCHAIN_PATH=%IDE_PATH%\ide\tools\bin
SET IDE=%IDE_PATH%\ide\mcuxpressoidec.exe
ECHO %PATH%|findstr /i /c:"%TOOLCHAIN_PATH:"=%">nul || set PATH=%PATH%;%TOOLCHAIN_PATH%
RD/S/Q "%SOURCE_PATH%\.metadata"
"%IDE%" -nosplash -application org.eclipse.cdt.managedbuilder.core.headlessbuild -data "%SOURCE_PATH%" -verbose -import "%SOURCE_PATH%\projects\evkmimxrt1060\bootloader" -build bootloader/Debug
"%IDE%" -nosplash -application org.eclipse.cdt.managedbuilder.core.headlessbuild -data "%SOURCE_PATH%" -verbose -import "%SOURCE_PATH%\projects\evkmimxrt1060\test" -build aws_iot_qual_test/Debug
py "%SOURCE_PATH%\Middleware\mcuboot\scripts\imgtool.py" sign -k %SOURCE_PATH%\examples\evkbmimxrt1060\bootloader\signing_key.pem --align 4  --header-size 0x400 --pad-header --slot-size 0x200000 --max-sectors 800 --version "1.0" --pad --confirm %SOURCE_PATH%\projects\evkmimxrt1060\test\Debug\aws_iot_qual_test.bin %SOURCE_PATH%\projects\evkmimxrt1060\test\Debug\aws_iot_qual_test_signed.bin
py "%SOURCE_PATH%\Middleware\mcuboot\scripts\imgtool.py" sign -k %SOURCE_PATH%\examples\evkbmimxrt1060\bootloader\signing_key.pem --align 4  --header-size 0x400 --pad-header --slot-size 0x200000 --max-sectors 800 --version "1.0" %SOURCE_PATH%\projects\evkmimxrt1060\test\Debug\aws_iot_qual_test.bin %SOURCE_PATH%\projects\evkmimxrt1060\test\Debug\aws_iot_qual_test_signed_OTA.bin