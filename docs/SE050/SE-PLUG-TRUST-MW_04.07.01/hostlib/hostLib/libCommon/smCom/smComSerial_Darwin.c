/*

 Based on:

     File: SerialPortSample.c
 Abstract: Command line tool that demonstrates how to use IOKitLib to find all serial ports on OS X. Also shows how to open, write to, read from, and close a serial port.
  Version: 1.5

 Disclaimer: IMPORTANT:  This Apple software is supplied to you by Apple
 Inc. ("Apple") in consideration of your agreement to the following
 terms, and your use, installation, modification or redistribution of
 this Apple software constitutes acceptance of these terms.  If you do
 not agree with these terms, please do not use, install, modify or
 redistribute this Apple software.

 In consideration of your agreement to abide by the following terms, and
 subject to these terms, Apple grants you a personal, non-exclusive
 license, under Apple's copyrights in this original Apple software (the
 "Apple Software"), to use, reproduce, modify and redistribute the Apple
 Software, with or without modifications, in source and/or binary forms;
 provided that if you redistribute the Apple Software in its entirety and
 without modifications, you must retain this notice and the following
 text and disclaimers in all such redistributions of the Apple Software.
 Neither the name, trademarks, service marks or logos of Apple Inc. may
 be used to endorse or promote products derived from the Apple Software
 without specific prior written permission from Apple.  Except as
 expressly stated in this notice, no other rights or licenses, express or
 implied, are granted by Apple herein, including but not limited to any
 patent rights that may be infringed by your derivative works or by other
 works in which the Apple Software may be incorporated.

 The Apple Software is provided by Apple on an "AS IS" basis.  APPLE
 MAKES NO WARRANTIES, EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 THE IMPLIED WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY AND FITNESS
 FOR A PARTICULAR PURPOSE, REGARDING THE APPLE SOFTWARE OR ITS USE AND
 OPERATION ALONE OR IN COMBINATION WITH YOUR PRODUCTS.

 IN NO EVENT SHALL APPLE BE LIABLE FOR ANY SPECIAL, INDIRECT, INCIDENTAL
 OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 INTERRUPTION) ARISING IN ANY WAY OUT OF THE USE, REPRODUCTION,
 MODIFICATION AND/OR DISTRIBUTION OF THE APPLE SOFTWARE, HOWEVER CAUSED
 AND WHETHER UNDER THEORY OF CONTRACT, TORT (INCLUDING NEGLIGENCE),
 STRICT LIABILITY OR OTHERWISE, EVEN IF APPLE HAS BEEN ADVISED OF THE
 POSSIBILITY OF SUCH DAMAGE.

 Copyright (C) 2013 Apple Inc. All Rights Reserved.
 Copyright (C) 2018-2020 NXP. All Rights Reserved.

 */

#include <stdio.h>

/*TODO Review */
#include "smComSerial.h"
#include <stdlib.h>
#include <stdio.h>
#include "string.h"
#include <assert.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <paths.h>
#include <termios.h>
#include <sysexits.h>
#include <sys/param.h>
#include <sys/select.h>
#include <sys/time.h>
#include <time.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/serial/IOSerialKeys.h>
#include <IOKit/serial/ioss.h>
#include <IOKit/IOBSD.h>
#include "sm_printf.h"
#include "smComSocket.h"
#include "nxLog_smCom.h"
#include "inttypes.h"
#include "nxEnsure.h"

#define REMOTE_JC_SHELL_HEADER_LEN (4)
#define REMOTE_JC_SHELL_MSG_TYPE_APDU_DATA (0x01)
#include "sm_apdu.h"
#define MAX_BUF_SIZE (MAX_APDU_BUF_LENGTH)

// Hold the original termios attributes so we can reset them
static struct termios gOriginalTTYAttrs;

static int fileDescriptor = -1;

U32 smComVCom_Open(void** vcom_ctx, const char *bsdPath)
{
    //int             handshake;
    struct termios options;
    if (bsdPath == NULL) {
        LOG_E("Need Serail port name");
        goto error;
    }

    // Open the serial port read/write, with no controlling terminal, and don't wait for a connection.
    // The O_NONBLOCK flag also causes subsequent I/O on the device to be non-blocking.
    // See open(2) <x-man-page://2/open> for details.

    fileDescriptor = open(bsdPath, O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (fileDescriptor == -1) {
        printf("Error opening serial port %s - %s(%d).\n", bsdPath, strerror(errno), errno);
        goto error;
    }

    // Note that open() follows POSIX semantics: multiple open() calls to the same file will succeed
    // unless the TIOCEXCL ioctl is issued. This will prevent additional opens except by root-owned
    // processes.
    // See tty(4) <x-man-page//4/tty> and ioctl(2) <x-man-page//2/ioctl> for details.

    if (ioctl(fileDescriptor, TIOCEXCL) == -1) {
        printf("Error setting TIOCEXCL on %s - %s(%d).\n", bsdPath, strerror(errno), errno);
        goto error;
    }

    // Now that the device is open, clear the O_NONBLOCK flag so subsequent I/O will block.
    // See fcntl(2) <x-man-page//2/fcntl> for details.

    if (fcntl(fileDescriptor, F_SETFL, 0) == -1) {
        printf("Error clearing O_NONBLOCK %s - %s(%d).\n", bsdPath, strerror(errno), errno);
        goto error;
    }

    // Get the current options and save them so we can restore the default settings later.
    if (tcgetattr(fileDescriptor, &gOriginalTTYAttrs) == -1) {
        printf("Error getting tty attributes %s - %s(%d).\n", bsdPath, strerror(errno), errno);
        goto error;
    }

    // The serial port attributes such as timeouts and baud rate are set by modifying the termios
    // structure and then calling tcsetattr() to cause the changes to take effect. Note that the
    // changes will not become effective without the tcsetattr() call.
    // See tcsetattr(4) <x-man-page://4/tcsetattr> for details.

    options = gOriginalTTYAttrs;

    // Print the current input and output baud rates.
    // See tcsetattr(4) <x-man-page://4/tcsetattr> for details.

    // printf("Current input baud rate is %d\n", (int) cfgetispeed(&options));
    // printf("Current output baud rate is %d\n", (int) cfgetospeed(&options));

    // Set raw input (non-canonical) mode, with reads blocking until either a single character
    // has been received or a one second timeout expires.
    // See tcsetattr(4) <x-man-page://4/tcsetattr> and termios(4) <x-man-page://4/termios> for details.

    cfmakeraw(&options);
    options.c_cc[VMIN] = 1;
    options.c_cc[VTIME] = 10;

    // The baud rate, word length, and handshake options can be set as follows:

    cfsetspeed(&options, B115200); // Set  baud
    options.c_cflag = CS8 | CREAD | CLOCAL;
    options.c_iflag = 0;
    options.c_oflag = ONOEOT;
    //options.c_oflag &= ~ONLCR;

    //    options.c_cflag |= (CS7        |    // Use 7 bit words
    //                        PARENB     |    // Parity enable (even parity if PARODD not also set)
    //                        CCTS_OFLOW |    // CTS flow control of output
    //                        CRTS_IFLOW);    // RTS flow control of input

    // The IOSSIOSPEED ioctl can be used to set arbitrary baud rates
    // other than those specified by POSIX. The driver for the underlying serial hardware
    // ultimately determines which baud rates can be used. This ioctl sets both the input
    // and output speed.

    // Cause the new options to take effect immediately.
    if (tcsetattr(fileDescriptor, TCSANOW, &options) == -1) {
        printf("Error setting tty attributes %s - %s(%d).\n", bsdPath, strerror(errno), errno);
        goto error;
    }

    speed_t speed = B115200; // Set 14400 baud
    if (ioctl(fileDescriptor, IOSSIOSPEED, &speed) == -1) {
        printf("Error calling ioctl(..., IOSSIOSPEED, ...) %s - %s(%d).\n", bsdPath, strerror(errno), errno);
    }

    // Print the new input and output baud rates. Note that the IOSSIOSPEED ioctl interacts with the serial driver
    // directly bypassing the termios struct. This means that the following two calls will not be able to read
    // the current baud rate if the IOSSIOSPEED ioctl was used but will instead return the speed set by the last call
    // to cfsetspeed.

    LOG_D("Input baud rate changed to %d\n", (int)cfgetispeed(&options));
    LOG_D("Output baud rate changed to %d\n", (int)cfgetospeed(&options));

    // To set the modem handshake lines, use the following ioctls.
    // See tty(4) <x-man-page//4/tty> and ioctl(2) <x-man-page//2/ioctl> for details.

    //    // Assert Data Terminal Ready (DTR)
    //    if (ioctl(fileDescriptor, TIOCSDTR) == -1) {
    //        printf("Error asserting DTR %s - %s(%d).\n",
    //            bsdPath, strerror(errno), errno);
    //    }
    //
    //    // sleep(1);
    //
    //    // // Clear Data Terminal Ready (DTR)
    //    if (ioctl(fileDescriptor, TIOCCDTR) == -1) {
    //        printf("Error clearing DTR %s - %s(%d).\n",
    //               bsdPath, strerror(errno), errno);
    //    }

    // sleep(1);

    //    // // Set the modem lines depending on the bits set in handshake
    //    handshake = 0;//TIOCM_DTR | TIOCM_RTS | TIOCM_CTS | TIOCM_DSR;
    //    if (ioctl(fileDescriptor, TIOCMSET, &handshake) == -1) {
    //      printf("Error setting handshake lines %s - %s(%d).\n",
    //             bsdPath, strerror(errno), errno);
    //    }

    // // To read the state of the modem lines, use the following ioctl.
    // // See tty(4) <x-man-page//4/tty> and ioctl(2) <x-man-page//2/ioctl> for details.

    // // Store the state of the modem lines in handshake
    // if (ioctl(fileDescriptor, TIOCMGET, &handshake) == -1) {
    //     printf("Error getting handshake lines %s - %s(%d).\n",
    //            bsdPath, strerror(errno), errno);
    // }

    // printf("Handshake lines currently set to %d\n", handshake);

    // unsigned long mics = 1UL;

    // // Set the receive latency in microseconds. Serial drivers use this value to determine how often to
    // // dequeue characters received by the hardware. Most applications don't need to set this value: if an
    // // app reads lines of characters, the app can't do anything until the line termination character has been
    // // received anyway. The most common applications which are sensitive to read latency are MIDI and IrDA
    // // applications.

    // if (ioctl(fileDescriptor, IOSSDATALAT, &mics) == -1) {
    //     // set latency to 1 microsecond
    //     printf("Error setting read latency %s - %s(%d).\n",
    //            bsdPath, strerror(errno), errno);
    //     goto error;
    // }

    smCom_Init(&smComVCom_Transceive, &smComVCom_TransceiveRaw);
    // Success
    return 0;

    // Failure path
error:
    if (fileDescriptor != -1) {
        close(fileDescriptor);
    }

    return (U32)-1;
}

U32 smComVCom_Close(void* conn_ctx)
{
    U32 status = 0;

    smComSocket_CloseFD(fileDescriptor);

    return status;
}

U32 smComVCom_GetATR(void* conn_ctx, U8 *pAtr, U16 *atrLen)
{
    return smComSocket_GetATRFD(fileDescriptor, pAtr, atrLen);
}

U32 smComVCom_Transceive(void* conn_ctx, apdu_t *pApdu)
{
    return smComSocket_TransceiveFD(fileDescriptor, pApdu);
}

U32 smComVCom_TransceiveRaw(void* conn_ctx, U8 *pTx, U16 txLen, U8 *pRx, U32 *pRxLen)
{
    return smComSocket_TransceiveRawFD(fileDescriptor, pTx, txLen, pRx, pRxLen);
}
