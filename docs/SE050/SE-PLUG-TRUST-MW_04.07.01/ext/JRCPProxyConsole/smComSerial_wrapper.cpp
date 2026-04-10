/* Copyright 2019 NXP
 *
 * This software is owned or controlled by NXP and may only be used
 * strictly in accordance with the applicable license terms.  By expressly
 * accepting such terms or by downloading, installing, activating and/or
 * otherwise using the software, you are agreeing that you have read, and
 * that you agree to comply with and are bound by, such license terms.  If
 * you do not agree to be bound by the applicable license terms, then you
 * may not retain, install, activate or otherwise use the software.
 */
#include "smComSerial_wrapper.hpp"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include "WinBase.h"
#include "WinDef.h"
#include "smComSerial.h"
#include "sm_printf.h"
#include "string.h"
#include "windows.h"

#define LOG_SOCK 1

using namespace std;

static U8 Header[2] = {0x01, 0x00};
static U8 sockapdu[MAX_BUF_SIZE];
static U8 response[MAX_BUF_SIZE];
static U8 *pCmd = (U8 *)&sockapdu;
static U8 *pRsp = (U8 *)&response;

static void *pComHandle = NULL;

SmComSerialWrapper::SmComSerialWrapper(SOCKET socket)
{
    clientSocket = socket;
}

static void jrcp_print_packet(
    const char *pString, const unsigned char *p_data, int len)
{
    int i;
    int length = len * 3 + 1;
    char *print_buffer = new char[length];
    memset(print_buffer, 0, sizeof(print_buffer));
    for (i = 0; i < len; i++) {
        snprintf(&print_buffer[i * 2], 3, "%02X", p_data[i]);
    }
    if (0 == memcmp(pString, "SEND", 0x04)) {
        printf(
            "JRCPServer Send to JCShell len = %3d > %s\n", len, print_buffer);
    }
    else if (0 == memcmp(pString, "RECV", 0x04)) {
        printf(
            "JRCPServer Recv from JCShell len = %3d < %s\n", len, print_buffer);
    }
    return;
}

int SmComSerialWrapper::jrcp_send_response()
{
    int ret;

    ret = JrcpSendMsg(&headerBuffer[0], JRCP_HEADER_LENGTH);
    if (ret != JRCP_HEADER_LENGTH) {
        cout << __FUNCTION__ << ":" << __LINE__ << ":  "
             << "send response failed\n";
        return -1;
    }

    ret = JrcpSendMsg(&outBuffer[0], outBuffer_len);
    if (ret != (int)outBuffer_len) {
        cout << __FUNCTION__ << ":" << __LINE__ << ":  "
             << "jrcp_send_response err sending data\n";
        return -1;
    }
    return ret;
}

static void escapeComPortName(char pOutPortName[20], const char *iPortName)
{
    strncpy(pOutPortName, iPortName, sizeof(pOutPortName));
    //strncpy_s(pOutPortName, sizeof(pOutPortName), iPortName, sizeof(pOutPortName));
    if (0 == _strnicmp(iPortName, "COM", 3)) {
        long number = atol(&iPortName[3]);
        if (number > 4) {
            _snprintf(pOutPortName, 20, "\\\\.\\%s", iPortName);
        }
    }
    else {
        _snprintf(pOutPortName, 20, "%s", iPortName);
    }
}

U32 SmComSerialWrapper::smComVCom_Open(const char *pComPortString)
{
    U32 status = 0;
    COMMTIMEOUTS cto;
    //	U8 pAtr[MAX_BUF_SIZE];
    //	U16 pAtrlen;
    char escaped_port_name[20] = {0};
#ifdef UNICODE
    wchar_t wPortName[20] = {0};
#endif
    /* Prepare CTO structure */
    cto.ReadTotalTimeoutConstant = 500;
    cto.ReadTotalTimeoutMultiplier = 0;
    cto.ReadIntervalTimeout = 10;
    cto.WriteTotalTimeoutConstant = 0;
    cto.WriteTotalTimeoutMultiplier = 0;

    escapeComPortName(escaped_port_name, pComPortString);

    printf("Opening COM Port '%s'\n", escaped_port_name);
#ifdef UNICODE
    mbstowcs(
        wPortName, escaped_port_name, sizeof(wPortName) / sizeof(wPortName[0]));
    pComHandle = CreateFile(wPortName,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);
#else
    pComHandle = CreateFile(escaped_port_name,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);
#endif

    status = GetLastError();

    if (status == ERROR_SUCCESS) {
        status = smComVCom_SetState();

        if (status == 0) {
            if (SetCommTimeouts(pComHandle, &cto) == false) {
                status = 1;
            }
        }
    }
    else if (ERROR_FILE_NOT_FOUND == status) {
        printf("ERROR! Failed opening '%s'. ERROR=ERROR_FILE_NOT_FOUND\n",
            pComPortString);
    }
    else if (ERROR_ACCESS_DENIED == status) {
        printf("ERROR! Failed opening '%s'. ERROR=ERROR_ACCESS_DENIED\n",
            pComPortString);
    }
    else if (pComHandle == INVALID_HANDLE_VALUE) {
        if (status == 0)
            status = 1; /* Over ride - it's a failure */
        printf("ERROR! Failed opening '%s'. ERROR=%X\n",
            escaped_port_name,
            status);
    }

    return status;
}

U32 SmComSerialWrapper::smComVCom_SetState(void)
{
    DCB dcb;
    memset(&dcb, 0, sizeof(dcb));

    dcb.DCBlength = sizeof(DCB);
    dcb.BaudRate = 115200;
    dcb.fBinary = true;
    dcb.fParity = false;
    dcb.fOutxCtsFlow = false;
    dcb.fOutxDsrFlow = false;
    dcb.fDtrControl = DTR_CONTROL_DISABLE;
    dcb.fDsrSensitivity = false;
    dcb.fTXContinueOnXoff = true;
    dcb.fOutX = false;
    dcb.fInX = false;
    dcb.fErrorChar = false;
    dcb.fNull = false;
    dcb.fRtsControl = RTS_CONTROL_DISABLE;
    dcb.fAbortOnError = false;
    dcb.XonLim = 0;
    dcb.XoffLim = 0;
    dcb.ByteSize = 8;
    dcb.Parity = NOPARITY;
    dcb.StopBits = ONESTOPBIT;

    if (SetCommState(pComHandle, &dcb) == false) {
        return 1;
    }
    else {
        EscapeCommFunction(pComHandle, SETDTR);
        return 0;
    }
}

U32 SmComSerialWrapper::smComVCom_CloseConn(U8* pRx, U16* pRxLen)
{
#define NAD 0x00

    int retval;

    U32 expectedLength = 0;
    U32 totalReceived = 0;
    U8 lengthReceived = 0;
    DWORD WrittenLen = 0;
    U8 status;

    // wait 256 ms
    U8 CloseCmd[8] = {0x03, NAD, 0, 4, 0, 0, 1, 0};
    jrcp_print_packet("SEND", static_cast<const unsigned char *>(CloseCmd), 8);
    status = WriteFile(pComHandle, CloseCmd, sizeof(CloseCmd), &WrittenLen, NULL);
    if ((status == 0) || (WrittenLen != sizeof(CloseCmd))) {
        return 1;
    }

    expectedLength =
        REMOTE_JC_SHELL_HEADER_LEN; // remote JC shell header length

    while (totalReceived < expectedLength) {
        U32 maxCommLength;
        DWORD numBytesRead = 0;
        if (lengthReceived == 0) {
            maxCommLength = REMOTE_JC_SHELL_HEADER_LEN - totalReceived;
        }
        else {
            maxCommLength = expectedLength - totalReceived;
        }

        status = ReadFile(pComHandle,
            (char *)&pRx[totalReceived],
            maxCommLength,
            &numBytesRead,
            NULL);
        retval = numBytesRead;
        if ((retval < 0) || (status == 0)) {
            fprintf(stderr, "Client: recv() failed: error %i.\n", retval);
            return 1;
        }
        else {
            totalReceived += retval;
        }
        if ((totalReceived >= REMOTE_JC_SHELL_HEADER_LEN) &&
            (lengthReceived == 0)) {
            expectedLength += ((pRx[2] << 8) | (pRx[3]));
            lengthReceived = 1;
        }
    }

    retval = totalReceived;

    retval -= 4; // Remove the 4 bytes of the Remote JC Terminal protocol
    memmove(pRx, pRx + 4, retval);

    *pRxLen = (U16)retval;
    return 0;
}

U32 SmComSerialWrapper::smComVCom_GetATR(U8 *pAtr, U16 *atrLen)
{
#define MTY 0
#define NAD 0x00

    int retval;

    U32 expectedLength = 0;
    U32 totalReceived = 0;
    U8 lengthReceived = 0;
    DWORD WrittenLen = 0;
    U8 status;

    // wait 256 ms
    U8 ATRCmd[8] = {MTY, NAD, 0, 4, 0, 0, 1, 0};
    jrcp_print_packet("SEND", static_cast<const unsigned char *>(ATRCmd), 8);
    status = WriteFile(pComHandle, ATRCmd, sizeof(ATRCmd), &WrittenLen, NULL);
    if ((status == 0) || (WrittenLen != sizeof(ATRCmd))) {
        return 1;
    }

    expectedLength =
        REMOTE_JC_SHELL_HEADER_LEN; // remote JC shell header length

    while (totalReceived < expectedLength) {
        U32 maxCommLength;
        DWORD numBytesRead = 0;
        if (lengthReceived == 0) {
            maxCommLength = REMOTE_JC_SHELL_HEADER_LEN - totalReceived;
        }
        else {
            maxCommLength = expectedLength - totalReceived;
        }

        status = ReadFile(pComHandle,
            (char *)&pAtr[totalReceived],
            maxCommLength,
            &numBytesRead,
            NULL);
        retval = numBytesRead;
        if ((retval < 0) || (status == 0)) {
            fprintf(stderr, "Client: recv() failed: error %i.\n", retval);
            return 1;
        }
        else {
            totalReceived += retval;
        }
        if ((totalReceived >= REMOTE_JC_SHELL_HEADER_LEN) &&
            (lengthReceived == 0)) {
            expectedLength += ((pAtr[2] << 8) | (pAtr[3]));
            lengthReceived = 1;
        }
    }
    retval = totalReceived;

    retval -= 4; // Remove the 4 bytes of the Remote JC Terminal protocol
    memmove(pAtr, pAtr + 4, retval);

    *atrLen = (U16)retval;
    return 0;
}

int SmComSerialWrapper::smComVcom_JrcpTransceive()
{
    int ret = 0;
    int respLength = 0x00;

    memset(&headerBuffer, 0x00, sizeof(JRCP_HEADER_LENGTH));
    memset(&dataBuffer, 0x00, sizeof(MAX_BUF_SIZE));
    memset(&outBuffer, 0x00, sizeof(MAX_BUF_SIZE));

    if ((headerBuffer_len =
                    JrcpReceiveMsg(&headerBuffer[0], JRCP_HEADER_LENGTH)) < 0 ){
        //to gracefully exit the session, send a custom command with start byte as 0x03
        unsigned char pRx[MAX_BUF_SIZE] = {0};
        U16 rxLen = 0;

        if (SMARTCARD_ERROR_NONE != smComVCom_CloseConn(pRx, &rxLen)) {
            cout << __FUNCTION__ << ":" << __LINE__ << ":"
                << "close_connection failed\n";
        }
        else {
            std::cout << __FUNCTION__ << ":" << __LINE__ << ":"
                << "close connect response length = " << rxLen << endl;
        }

        if (!closeOn_exit) {
            return 2;
        }
        return 1;
    }

    cout << "headerBuffer_len = " << headerBuffer_len << endl;
    if (headerBuffer_len == 5 && headerBuffer[0] == 0xFF) {
        cout << __FUNCTION__ << ":" << __LINE__ << ":"
             << "Reset SMX" << endl;
    }
    if (headerBuffer_len != JRCP_HEADER_LENGTH) {
        cout << __FUNCTION__ << ":" << __LINE__ << ":"
             << "Bad data header" << endl;
        return 1;
    }

    respLength = (int)(0x0000FF00 & (headerBuffer[JRCP_LNH_OFFSET]) << 8);

    respLength |= headerBuffer[JRCP_LNL_OFFSET];

    if ((dataBuffer_len = JrcpReceiveMsg(&dataBuffer[0], respLength)) < 0) {
        cout << __FUNCTION__ << ":" << __LINE__ << ":"
             << "read data error" << errno << endl;
        return 1;
    }

    switch (headerBuffer[JRCP_MTY_OFFSET]) {
    case JRCP_WAIT_FOR_CARD: {
        cout << __FUNCTION__ << ":" << __LINE__ << ":  "
             << "retreive ATR\n";
        unsigned char pAtr[MAX_BUF_SIZE] = {0};
        U16 len = 0;
        if (SMARTCARD_ERROR_NONE != smComVCom_GetATR(pAtr, &len)) {
            cout << __FUNCTION__ << ":" << __LINE__ << ":"
                 << "smartcard_get_atr failed\n";
            jcrp_failed_status();
        }
        else {
            std::cout << __FUNCTION__ << ":" << __LINE__ << ":"
                      << "atr length = " << len << endl;
            memcpy(&outBuffer[0], &pAtr[0], len);
            outBuffer_len = len;
            updateHeaderLen(&headerBuffer[0], (outBuffer_len));
        }
    } break;

    case JRCP_APDU_DATA: {
        //		unsigned char * ptransmitResponse;
        if (dataBuffer[0] == 0x00 && dataBuffer[1] == 0xA4) {
            cout << "select cmd." << endl;
        }

        ret = smComVCom_TransceiveRaw(
            dataBuffer, dataBuffer_len, outBuffer, &outBuffer_len);

        if (ret != JCSHELL_ERROR_NONE) {
            cout << __FUNCTION__ << ":" << __LINE__ << ":  "
                 << "smartcard_channel_transmit failed ret = " << ret << endl;
            jcrp_failed_status();
        }
        updateHeaderLen(&headerBuffer[0], (outBuffer_len));
    }

    break;

    case JRCP_STATUS: {
        cout << __FUNCTION__ << ":" << __LINE__ << ":  "
             << "JRCP_STATUS cmd.\n";
        loopbackTest();
    } break;
    case JRCP_ERROR_MESSAGE: {
        cout << __FUNCTION__ << ":" << __LINE__ << ":  "
             << "JRCP_ERROR_MESSAGE cmd\n";
        loopbackTest();
    } break;
    case JRCP_TERMINAL_INFO: {
        cout << __FUNCTION__ << ":" << __LINE__ << ":  "
             << "JRCP_TERMINAL_INFO cmd\n";
        replyTerminalInfo();
    } break;
    case JRCP_INIT_INFO: {
        cout << __FUNCTION__ << ":" << __LINE__ << ":  "
             << "JRCP_INIT_INFO cmd\n";
        loopbackTest();
    } break;
    case JRCP_ECHO: {
        cout << __FUNCTION__ << ":" << __LINE__ << ":  "
             << "JRCP_ECHO cmd\n";
        loopbackTest();
    } break;
    case JRCP_DEBUG: {
        cout << __FUNCTION__ << ":" << __LINE__ << ":  "
             << "JRCP_DEBUG cmd\n";
        loopbackTest();
    } break;
    default: {
        cout << __FUNCTION__ << ":" << __LINE__ << ":  "
             << "Unknown cmd\n";
        loopbackTest();
    } break;
    }
    ret = jrcp_send_response();
    if (ret > -1)
        ret = 0;
    return ret;
}

U32 SmComSerialWrapper::smComVCom_Transceive(apdu_t *pApdu)
{
    int retval;
#if defined(LOG_SOCK)
    int i;
#endif
    U32 txLen = 0;
    U32 expectedLength = 0;
    U32 totalReceived = 0;
    U8 lengthReceived = 0;
    U8 status;
    DWORD WrittenLen = 0;

    //    assert(pApdu != NULL);

    pApdu->rxlen = 0;

    memset(sockapdu, 0x00, MAX_BUF_SIZE);
    memset(response, 0x00, MAX_BUF_SIZE);

    // remote JC Terminal header construction
    txLen = pApdu->buflen;
    memcpy(pCmd, Header, sizeof(Header));
    pCmd[2] = (txLen & 0xFF00) >> 8;
    pCmd[3] = txLen & 0xFF;
    memcpy(&pCmd[4], pApdu->pBuf, pApdu->buflen);
    pApdu->buflen += 4; /* header & length */

#ifdef LOG_SOCK
    sm_printf(CONSOLE, "   send: ");
    for (i = 4; i < ((int)txLen + 4); i++) {
        sm_printf(CONSOLE, "%02X", pCmd[i]);
    }
    sm_printf(CONSOLE, "\n");
#endif

    status = WriteFile(pComHandle, pCmd, pApdu->buflen, &WrittenLen, NULL);
    if ((status == 0) || (WrittenLen != pApdu->buflen)) {
        fprintf(stderr, "Client: send() failed: error %i.\n", WrittenLen);
        return SMCOM_SND_FAILED;
    }

    expectedLength =
        REMOTE_JC_SHELL_HEADER_LEN; // remote JC shell header length

    while (totalReceived < expectedLength) {
        DWORD numBytesRead = 0;
        status = ReadFile(pComHandle,
            (char *)&pRsp[totalReceived],
            MAX_BUF_SIZE,
            &numBytesRead,
            NULL);
        retval = numBytesRead;

        if ((retval < 0) || (status == 0)) {
            fprintf(stderr, "Client: recv() failed: error %i.\n", retval);
            //           assert(0);
            return SMCOM_RCV_FAILED;
        }
        else {
            totalReceived += retval;
        }
        if ((totalReceived >= REMOTE_JC_SHELL_HEADER_LEN) &&
            (lengthReceived == 0)) {
            expectedLength += ((pRsp[2] << 8) | (pRsp[3]));
            lengthReceived = 1;
        }
    }
    retval = totalReceived;

    retval -= 4; // Remove the 4 bytes of the Remote JC Terminal protocol
    memcpy(pApdu->pBuf, &pRsp[4], retval);

#ifdef LOG_SOCK
    sm_printf(CONSOLE, "   recv: ");
    for (i = 0; i < retval; i++) {
        sm_printf(CONSOLE, "%02X", pApdu->pBuf[i]);
    }
    sm_printf(CONSOLE, "\n");
#endif

    pApdu->rxlen = (U16)retval;
    // reset offset for subsequent response parsing
    pApdu->offset = 0;
    return SMCOM_OK;
}

U32 SmComSerialWrapper::smComVCom_TransceiveRaw(
    U8 *pTx, U16 txLen, U8 *pRx, U32 *pRxLen)
{
    S32 retval;
    U32 answerReceived = 0;
    U32 len = 0;
    U8 status = 0;
    DWORD WrittenLen = 0;
#if defined(LOG_SOCK) || defined(DBG_LOG_SOCK)
    int i;
#endif
    U32 readOffset = 0;
    U8 headerParsed = 0;
    U8 correctHeader = 0;
    memset(sockapdu, 0x00, MAX_BUF_SIZE);
    memset(response, 0x00, MAX_BUF_SIZE);

    memcpy(pCmd, Header, 2);
    pCmd[2] = (txLen & 0xFF00) >> 8;
    pCmd[3] = (txLen & 0x00FF);
    memcpy(&pCmd[4], pTx, txLen);
    txLen += 4; /* header + len */

#ifdef DBG_LOG_SOCK
    sm_printf(CONSOLE, "   full send: ");
    for (i = 0; i < txLen; i++) {
        sm_printf(CONSOLE, "%02X", pCmd[i]);
    }
    sm_printf(CONSOLE, "\n");
#endif

    status = WriteFile(pComHandle, pCmd, txLen, &WrittenLen, NULL);
    if ((status == false) || (WrittenLen != txLen)) {
        fprintf(stderr, "Client: send() failed: error %i.\n", WrittenLen);
        return SMCOM_SND_FAILED;
    }
    else {
#ifdef DBG_LOG_SOCK
        sm_printf(CONSOLE, "Client: send() is OK.\n");
#endif
    }

#ifdef LOG_SOCK
    sm_printf(CONSOLE, "   send: ");
    for (i = 4; i < txLen; i++) {
        sm_printf(CONSOLE, "%02X", pCmd[i]);
    }
    sm_printf(CONSOLE, "\n");
#endif

    retval =
        REMOTE_JC_SHELL_HEADER_LEN; // receive at least the JCTerminal header

    while ((retval > 0) || (answerReceived == 0)) {
        status = ReadFile(
            pComHandle, (char *)pRsp, MAX_BUF_SIZE, (LPDWORD)&retval, NULL);

        if ((retval < 0) || (status == 0)) {
            return SMCOM_RCV_FAILED;
        }
        else // data received
        {
            while (retval > 0) // parse all bytes
            {
                if (headerParsed == 1) // header already parsed; get data
                {
                    if (retval >= (S32)len) {
                        if (correctHeader == 1) {
                            memcpy(&pRx[0], &pRsp[readOffset], len);
                            answerReceived = 1;
                        }
                        else {
                            // reset header parsed
                            readOffset += len;
                            headerParsed = 0;
                        }
                        retval -= len;

                        if (retval == 0) // no data left, reset readOffset
                        {
                            readOffset = 0;
                        }
                    }
                    else {
                        // data too small according header => Error
                        fprintf(
                            stderr, "Failed reading data %x %x\n", retval, len);
                        return SMCOM_RCV_FAILED;
                    }
                }
                else // parse header
                {
                    len =
                        ((pRsp[readOffset + 2] << 8) | (pRsp[readOffset + 3]));

                    if (pRsp[readOffset] ==
                        REMOTE_JC_SHELL_MSG_TYPE_APDU_DATA) {
                        // type correct => copy the data
                        retval -= REMOTE_JC_SHELL_HEADER_LEN;
                        if (retval > 0) // data left to read
                        {
                            readOffset += REMOTE_JC_SHELL_HEADER_LEN;
                        }
                        correctHeader = 1;
                    }
                    else {
                        // type incorrect => skip the data as well and try again if data are left
                        readOffset += REMOTE_JC_SHELL_HEADER_LEN;
                        retval -= REMOTE_JC_SHELL_HEADER_LEN;
                        correctHeader = 0;
                    }
                    headerParsed = 1;
                }
            }
        }
    }

#ifdef LOG_SOCK
    sm_printf(CONSOLE, "   recv: ");
    for (i = 0; i < (int)len; i++) {
        sm_printf(CONSOLE, "%02X", pRx[i]);
    }
    sm_printf(CONSOLE, "\n");
#endif

    *pRxLen = len;

    return SMCOM_OK;
}

int SmComSerialWrapper::JrcpReceiveMsg(
    void *ptr_msg_buff, unsigned int data_len)
{
    int read_byte_count = -1;
    int total_recv_byte = -1;

    if (data_len == 0) {
        return 0;
    }
    if (NULL == ptr_msg_buff) {
        cout << __FUNCTION__ << ":" << __LINE__ << ":  "
             << "msg buffer is null\n";
        return -1;
    }
    memset(ptr_msg_buff, '\0', data_len);
    total_recv_byte = 0;
    do {
        read_byte_count = recv(clientSocket,
            (char *)ptr_msg_buff + total_recv_byte,
            (data_len - total_recv_byte),
            0);
        if (read_byte_count < 0) {
            cout << __FUNCTION__ << ":" << __LINE__ << ":  "
                 << "received failed" << endl;
            goto error;
        }
        if (read_byte_count == 0 ) {
            cout << __FUNCTION__ << ":" << __LINE__ << ":  "
                 << "read_byte_count = 0" << endl;
            return -1;
		}
        total_recv_byte += read_byte_count;
    } while (total_recv_byte < (int)data_len);

    jrcp_print_packet("RECV",
        static_cast<const unsigned char *>(ptr_msg_buff),
        total_recv_byte);

    return total_recv_byte;

error:
    return -1;
}

int SmComSerialWrapper::JrcpSendMsg(void *ptr_msg_buff, unsigned int len)
{
    int send_byte_count, total_send_byte;
    unsigned int mlen;

    mlen = len;
    total_send_byte = 0;
    do {
        //socket_state = SOCEKET_WRITE_PENDING;
        send_byte_count = send(clientSocket,
            ((char *)ptr_msg_buff) + total_send_byte,
            len - total_send_byte,
            0);
        if (send_byte_count < 0) {
            cout << __FUNCTION__ << ":" << __LINE__ << ":  "
                 << "Error in send\n";
            return -1;
        }
        total_send_byte += send_byte_count;
    } while (total_send_byte < (int)len);
    jrcp_print_packet("SEND",
        static_cast<const unsigned char *>(ptr_msg_buff),
        total_send_byte);
    //socket_state = SOCKET_IDLE;
    return len;
}

void SmComSerialWrapper::updateHeaderLen(unsigned char *header, int len)
{
    header[JRCP_LNH_OFFSET] = (unsigned char)((len >> 8) & 0xFF);
    header[JRCP_LNL_OFFSET] = (unsigned char)(len & 0xFF);
}

void SmComSerialWrapper::jcrp_failed_status(void)
{
    outBuffer[0] = 0x64;
    outBuffer[1] = 0xFF;
    outBuffer_len = 2;
    updateHeaderLen(&headerBuffer[0], (outBuffer_len));
}

void SmComSerialWrapper::loopbackTest(void)
{
    outBuffer_len = dataBuffer_len;
    outBuffer[outBuffer_len] = 0x90;
    outBuffer[outBuffer_len + 1] = 0x00;
    updateHeaderLen(&headerBuffer[0], (outBuffer_len));
}

void SmComSerialWrapper::replyTerminalInfo(void)
{
    //JCshell expects date and time string for Terminal info, hardcoded values send here
    strcpy((char *)(&outBuffer[0]), "2016-02-05 14:34:26");
    outBuffer_len = 0x13;
    updateHeaderLen(&headerBuffer[0], (outBuffer_len));
}

U16 SmComSerialWrapper::smComVCom_Close(void)
{
    U16 status;
    DWORD returncode;

    status = CloseHandle(pComHandle);

    if (status != 0) {
        returncode = GetLastError();
    }

    return status;
}
