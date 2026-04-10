/*
 * Copyright 2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */


#include "test_Crypto.h"

#define MAC_BLOCK_SIZE 16

/* clang-format off */
const uint8_t gSRCData1[MAC_BLOCK_SIZE] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
const uint8_t gSRCData2[] = {
    0x84,0x82,0x33,0x00,0x10,0xB3,0x60,0x8B,0x7A,0x4C,0xC3,0xA1,0x49,
    0x84,0x82,0x33,0x00,0x10,0xB3,0x60,0x8B,0x7A,0x4C,0xC3,0xA1,0x49,
    0x84,0x82,0x33,0x00,0x10,0xB3,0x60,0x8B,0x7A,0x4C,0xC3,0xA1,0x49,
    0x84,0x82,0x33,0x00,0x10,0xB3,0x60,0x8B,0x7A,0x4C,0xC3,0xA1,0x49,
    0x84,0x82,0x33,0x00,0x10,0xB3,0x60,0x8B,0x7A,0x4C,0xC3,0xA1,0x49,
    0x84,0x82,0x33,0x00,0x10,0xB3,0x60,0x8B,0x7A,0x4C,0xC3,0xA1,0x49,
    0x84,0x82,0x33,0x00,0x10,0xB3,0x60,0x8B,0x7A,0x4C,0xC3,0xA1,
};
const uint8_t srcData3[] = {
    0x84, 0x01, 0x03, 0x00, 0x28, 0x82, 0x7B, 0x9B, 0xBD, 0x3F, 0xDC, 0x41, 0x8C, 0x46, 0xBB, 0x42, 0xD4, 0x9A, 0x32, 0xC7, 0x0C, 0x0F,
    0x52, 0xB8, 0x6B, 0x24, 0x13, 0x73, 0xFF, 1,2,3,4,5,6,6,7,8,9,0,1,2,3,4,5,6,7,9, 10,
    0x52, 0xB8, 0x6B, 0x24, 0x13, 0x73, 0xFF, 1,2,3,4,5,6,6,7,8,9,0,1,2,3,4,5,6,7,9, 10,
    0x52, 0xB8, 0x6B, 0x24, 0x13, 0x73, 0xFF, 1,2,3,4,5,6,6,7,8,9,0,1,2,3,4,5,6,7,9, 10, 11, 1,2,3,4,5,
    0x52, 0xB8, 0x6B, 0x24, 0x13, 0x73, 0xFF, 1,2,3,4,5,6,6,7,8,9,0,1,2,3,4,5,6,7,9, 10,
    0x03, 0x61, 0x5E, 0x97, 0xA6, 0xDD, 0x8C, 0x18 };
const uint8_t srcData4[] = {
    0x28, 0x82, 0x7B, 0x9B, 0xBD, 0x3F, 0xDC, 0x41, 0x8C, 0x46, 0xBB, 0x42, 0xD4, 0x9A, 0x32, 0xC7, 0x0C, 0x0F,
    0x13, 0x73, 0xFF, 1,2,3,4,5,6,6,7,8,9,0,1,2,3,4,5,6,7,9, 10,
    0x13, 0x73, 0xFF, 1,2,3,4,5,6,6,7,8,9,0,1,2,3,4,5,6,7,9, 10,
    0x13, 0x73, 0xFF, 1,2,3,4,5,6,6,7,8,9,0,1,2,3,4,5,6,7,9, 10, 11, 1,2,3,4,5,
    0x13, 0x73, 0xFF, 1,2,3,4,5,6,6,7,8,9,0,1,2,3,4,5,6,7,9, 10,
    0xA6, 0xDD, 0x8C, 0x18 };

const uint8_t keystring[MAC_BLOCK_SIZE] = { 0xB3,0x35,0xFB,0xB5,0x14,0x00,0xB8,0x0B,0xB3,0x9B,0xE1,0xBF,0xD9,0x32,0x78,0x8C };
/* clang-format on */

static sss_status_t test_mac_multiStep_algo(userCtx_t *pUserCtx,
    const uint8_t expectedData[MAC_BLOCK_SIZE],
    const uint16_t srcData1Len,
    const uint16_t srcData2Len,
    const uint16_t srcData3Len,
    const uint16_t srcData4Len
);





sss_status_t test_mac_multiStep_algo_mmm(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] =         {0x90,0xFA,0x63,0x22,0x11,0x9D,0x60,0xDB,0x82,0x9D,0xC7,0xCF,0xC3,0x98,0x35,0x6C,};


    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) - 1,
        (MAC_BLOCK_SIZE * 4) - 1,
        (MAC_BLOCK_SIZE * 4) - 1);
    return status;
}


sss_status_t test_mac_multiStep_algo_mmz(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] =
            {0xF5,0x89,0x46,0x96,0x10,0x1B,0x57,0x37,0xD1,0xC5,0x62,0x16,0x9D,0xFF,0x88,0x03,};

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) - 1,
        (MAC_BLOCK_SIZE * 4) - 1,
        (MAC_BLOCK_SIZE * 4));
    return status;
}


sss_status_t test_mac_multiStep_algo_mmp(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] =
            {0xD1,0x05,0x5E,0xF8,0x98,0xFF,0x74,0xF0,0xFC,0x44,0x79,0xE5,0xD9,0x52,0x34,0xEE,};

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) - 1,
        (MAC_BLOCK_SIZE * 4) - 1,
        (MAC_BLOCK_SIZE * 4) + 1);
    return status;
}


sss_status_t test_mac_multiStep_algo_mmq(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] =
            {0x6C,0xEB,0x44,0x3F,0xAF,0x8D,0x21,0x78,0x08,0xD0,0x7B,0xC8,0xF0,0x16,0x03,0x4B,};


    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) - 1,
        (MAC_BLOCK_SIZE * 4) - 1,
        (MAC_BLOCK_SIZE * 4) * 0);
    return status;
}


sss_status_t test_mac_multiStep_algo_mzm(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] =
            {0xC0,0x80,0xB8,0x40,0x88,0xC4,0x0E,0x98,0x24,0xA8,0x93,0xD0,0xA1,0xC9,0xD1,0x29,};


    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) - 1,
        (MAC_BLOCK_SIZE * 4),
        (MAC_BLOCK_SIZE * 4) - 1);
    return status;
}


sss_status_t test_mac_multiStep_algo_mzz(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] =         {0x10,0xEF,0xEE,0x75,0xFD,0xE7,0xDF,0xD9,0x45,0xE5,0x98,0xE3,0x31,0x34,0xF8,0x6A,};


    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) - 1,
        (MAC_BLOCK_SIZE * 4),
        (MAC_BLOCK_SIZE * 4));
    return status;
}


sss_status_t test_mac_multiStep_algo_mzp(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] =         {0xD4,0xB0,0xD8,0x39,0x31,0x07,0x78,0xD2,0x9D,0x51,0x2D,0x97,0x6B,0x05,0x07,0xC2,};

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) - 1,
        (MAC_BLOCK_SIZE * 4),
        (MAC_BLOCK_SIZE * 4) + 1);
    return status;
}


sss_status_t test_mac_multiStep_algo_mzq(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] =         {0x06,0xD2,0xB2,0x05,0x6F,0x6C,0x6C,0x44,0xF6,0xDD,0x51,0x9A,0x0D,0x7B,0x33,0x47,};


    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) - 1,
        (MAC_BLOCK_SIZE * 4),
        (MAC_BLOCK_SIZE * 4) * 0);
    return status;
}


sss_status_t test_mac_multiStep_algo_mpm(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] =         {0xB6,0xE3,0x43,0x83,0xC1,0x33,0x4B,0x07,0xD8,0x3C,0xB4,0xDA,0xC2,0x7F,0xB1,0x56,};


    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) - 1,
        (MAC_BLOCK_SIZE * 4) + 1,
        (MAC_BLOCK_SIZE * 4) - 1);
    return status;
}


sss_status_t test_mac_multiStep_algo_mpz(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] =
    { 0x2C,0x86,0x75,0x84,0xD7,0x25,0x75,0x56,0x5A,0xE3,0xDA,0x8A,0x76,0xD5,0x20,0x78, };

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) - 1,
        (MAC_BLOCK_SIZE * 4) + 1,
        (MAC_BLOCK_SIZE * 4));
    return status;
}


sss_status_t test_mac_multiStep_algo_mpp(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] = { 0x29,0x34,0xF6,0xE5,0xC5,0x1D,0x99,0xC6,0xB7,0x39,0x71,0xC9,0xAC,0x06,0xD1,0x35, };

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) - 1,
        (MAC_BLOCK_SIZE * 4) + 1,
        (MAC_BLOCK_SIZE * 4) + 1);
    return status;
}


sss_status_t test_mac_multiStep_algo_mpq(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] =         {0x71,0x12,0x09,0x62,0x81,0x25,0x54,0xF4,0x7B,0x09,0x1F,0xB9,0xE6,0x23,0x7E,0x3D,};


    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) - 1,
        (MAC_BLOCK_SIZE * 4) + 1,
        (MAC_BLOCK_SIZE * 4) * 0);
    return status;
}


sss_status_t test_mac_multiStep_algo_mqm(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] =         {0x8D,0xF2,0x84,0xE5,0x30,0xA0,0x1A,0x01,0xDF,0x84,0x6E,0x88,0xB1,0x6C,0xC2,0x50,};

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) - 1,
        (MAC_BLOCK_SIZE * 4) * 0,
        (MAC_BLOCK_SIZE * 4) - 1);
    return status;
}


sss_status_t test_mac_multiStep_algo_mqz(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] =
    { 0x80,0x5C,0xD9,0xBB,0x9E,0x6F,0xBB,0x98,0x1C,0xF1,0x7C,0x89,0x6B,0x05,0x86,0x73, };
    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) - 1,
        (MAC_BLOCK_SIZE * 4) * 0,
        (MAC_BLOCK_SIZE * 4));
    return status;
}


sss_status_t test_mac_multiStep_algo_mqp(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] =
            {0x6E,0xCC,0x06,0xED,0xC9,0x55,0xED,0xC6,0xA1,0x41,0x0A,0xE2,0xB7,0xF5,0x9E,0x82,};

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) - 1,
        (MAC_BLOCK_SIZE * 4) * 0,
        (MAC_BLOCK_SIZE * 4) + 1);
    return status;
}


sss_status_t test_mac_multiStep_algo_mqq(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] =         {0x5E,0xDC,0x15,0x66,0xE0,0x67,0x89,0xF8,0x2C,0x2A,0xC3,0xC4,0x53,0xC1,0x1C,0x01,};

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) - 1,
        (MAC_BLOCK_SIZE * 4) * 0,
        (MAC_BLOCK_SIZE * 4) * 0);
    return status;
}


sss_status_t test_mac_multiStep_algo_zmm(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] =
            {0xD7,0xE2,0x26,0x83,0xC6,0xC5,0x35,0xD0,0xEE,0x7D,0xB0,0x12,0x49,0xF0,0x54,0x10,};

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4),
        (MAC_BLOCK_SIZE * 4) - 1,
        (MAC_BLOCK_SIZE * 4) - 1);
    return status;
}


sss_status_t test_mac_multiStep_algo_zmz(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] =
    { 0xC8,0xDC,0xC5,0xBC,0x31,0x3D,0x7F,0x8F,0xA1,0x76,0x47,0xF1,0xBD,0xED,0xFF,0xCE, };
    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4),
        (MAC_BLOCK_SIZE * 4) - 1,
        (MAC_BLOCK_SIZE * 4));
    return status;
}


sss_status_t test_mac_multiStep_algo_zmp(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] = { 0xCA,0x15,0xFF,0x1B,0xE1,0x2A,0xAC,0x2C,0xF5,0x8E,0x57,0x3B,0x7B,0x18,0x27,0x63, };;

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4),
        (MAC_BLOCK_SIZE * 4) - 1,
        (MAC_BLOCK_SIZE * 4) + 1);
    return status;
}


sss_status_t test_mac_multiStep_algo_zmq(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] = { 0x51,0x71,0x68,0xAE,0x0D,0x71,0x00,0x38,0x25,0x90,0xD4,0x20,0x6C,0xDA,0x4C,0xBE, };;

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4),
        (MAC_BLOCK_SIZE * 4) - 1,
        (MAC_BLOCK_SIZE * 4) * 0);
    return status;
}


sss_status_t test_mac_multiStep_algo_zzm(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] = { 0x15,0x5D,0xF8,0x66,0x68,0xD8,0x48,0xB9,0x6C,0x32,0x41,0x34,0x1B,0x59,0x2A,0x62, };;

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4),
        (MAC_BLOCK_SIZE * 4),
        (MAC_BLOCK_SIZE * 4) - 1);
    return status;
}


sss_status_t test_mac_multiStep_algo_zzz(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] = { 0x59,0x3D,0x3F,0x51,0x75,0xED,0x59,0x17,0xF4,0x2D,0x1F,0xEF,0x9F,0x52,0xBF,0x53, };;

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4),
        (MAC_BLOCK_SIZE * 4),
        (MAC_BLOCK_SIZE * 4));
    return status;
}


sss_status_t test_mac_multiStep_algo_zzp(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] = { 0x9A,0xB9,0xCB,0xE5,0x79,0x50,0xF3,0x78,0x66,0xCF,0x6E,0x4A,0xA5,0x77,0x50,0x1F, };;

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4),
        (MAC_BLOCK_SIZE * 4),
        (MAC_BLOCK_SIZE * 4) + 1);
    return status;
}


sss_status_t test_mac_multiStep_algo_zzq(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] = { 0xAB,0xA8,0x71,0x31,0xAC,0x2A,0x1A,0x1A,0xA6,0x5A,0x32,0xEB,0x51,0x64,0x1F,0x29, };;

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4),
        (MAC_BLOCK_SIZE * 4),
        (MAC_BLOCK_SIZE * 4) * 0);
    return status;
}


sss_status_t test_mac_multiStep_algo_zpm(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] = { 0x72,0xCF,0xEB,0xC5,0x5E,0xA0,0xD9,0x36,0x53,0xB6,0x8F,0xF7,0x7E,0xD8,0x75,0xE0, };;

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4),
        (MAC_BLOCK_SIZE * 4) + 1,
        (MAC_BLOCK_SIZE * 4) - 1);
    return status;
}


sss_status_t test_mac_multiStep_algo_zpz(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] = { 0xB0,0x50,0x69,0x02,0x73,0x9D,0x0A,0x73,0x46,0x15,0xC7,0x76,0xC7,0x25,0x25,0xEF, };


    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4),
        (MAC_BLOCK_SIZE * 4) + 1,
        (MAC_BLOCK_SIZE * 4));
    return status;
}


sss_status_t test_mac_multiStep_algo_zpp(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] = { 0xF0,0x26,0xF3,0xEF,0xAE,0x80,0x65,0xE5,0x45,0x23,0xF0,0xF6,0xBC,0xD0,0x7D,0x54, };

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4),
        (MAC_BLOCK_SIZE * 4) + 1,
        (MAC_BLOCK_SIZE * 4) + 1);
    return status;
}


sss_status_t test_mac_multiStep_algo_zpq(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] = { 0x78,0x31,0x80,0x6A,0xEE,0xC4,0xE5,0x22,0x08,0x03,0xE6,0x1C,0x80,0x96,0xBB,0x8F, };

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4),
        (MAC_BLOCK_SIZE * 4) + 1,
        (MAC_BLOCK_SIZE * 4) * 0);
    return status;
}


sss_status_t test_mac_multiStep_algo_zqm(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] = { 0x52,0xD2,0x2B,0x58,0xC9,0x90,0xDA,0xA0,0x85,0x9B,0x98,0xE2,0x23,0xB8,0xF6,0x0B, };

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4),
        (MAC_BLOCK_SIZE * 4) * 0,
        (MAC_BLOCK_SIZE * 4) - 1);
    return status;
}


sss_status_t test_mac_multiStep_algo_zqz(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] = { 0xC5,0x75,0xC5,0x03,0x9F,0x31,0xDF,0x67,0xCF,0x05,0xCB,0xE3,0xD4,0x9D,0x5E,0x08, };

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4),
        (MAC_BLOCK_SIZE * 4) * 0,
        (MAC_BLOCK_SIZE * 4));
    return status;
}


sss_status_t test_mac_multiStep_algo_zqp(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] = { 0x33,0x94,0xBA,0x46,0xFF,0x8E,0x5E,0x82,0xB2,0xFF,0x7A,0xCB,0xBA,0x27,0x85,0x57, };

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4),
        (MAC_BLOCK_SIZE * 4) * 0,
        (MAC_BLOCK_SIZE * 4) + 1);
    return status;
}


sss_status_t test_mac_multiStep_algo_zqq(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] = { 0x3A,0x98,0x00,0xFF,0x90,0x63,0x90,0x16,0x41,0xB8,0xFF,0x2B,0xF9,0x30,0xB5,0xE1, };

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4),
        (MAC_BLOCK_SIZE * 4) * 0,
        (MAC_BLOCK_SIZE * 4) * 0);
    return status;
}


sss_status_t test_mac_multiStep_algo_pmm(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] = { 0x42,0xF5,0x9A,0x2B,0x3A,0xC6,0x85,0x87,0x8F,0xE4,0x46,0x03,0x94,0x3D,0x5D,0xF7, };

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) + 1,
        (MAC_BLOCK_SIZE * 4) - 1,
        (MAC_BLOCK_SIZE * 4) - 1);
    return status;
}


sss_status_t test_mac_multiStep_algo_pmz(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] = { 0x2F,0xB3,0x72,0xAE,0x9E,0xC3,0x41,0xE9,0x6F,0x35,0x67,0xB8,0xB3,0x0A,0x4C,0x4B, };

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) + 1,
        (MAC_BLOCK_SIZE * 4) - 1,
        (MAC_BLOCK_SIZE * 4));
    return status;
}


sss_status_t test_mac_multiStep_algo_pmp(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] = { 0xDE,0x6B,0x4C,0xC8,0x39,0xDB,0xDB,0xE4,0x65,0x9B,0x5A,0x2A,0x9F,0x7D,0xA5,0xA2, };

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) + 1,
        (MAC_BLOCK_SIZE * 4) - 1,
        (MAC_BLOCK_SIZE * 4) + 1);
    return status;
}


sss_status_t test_mac_multiStep_algo_pmq(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] = { 0xE6,0x0B,0x48,0x5A,0x7E,0xB6,0xC0,0x48,0xA9,0xA6,0xCE,0xE5,0x1D,0x16,0x8B,0xD3, };

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) + 1,
        (MAC_BLOCK_SIZE * 4) - 1,
        (MAC_BLOCK_SIZE * 4) * 0);
    return status;
}


sss_status_t test_mac_multiStep_algo_pzm(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] = { 0xBB,0xA4,0x76,0x83,0x2B,0xEA,0xEA,0x7D,0x4D,0x77,0x0D,0x07,0x19,0xC5,0x87,0x3D, };

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) + 1,
        (MAC_BLOCK_SIZE * 4),
        (MAC_BLOCK_SIZE * 4) - 1);
    return status;
}


sss_status_t test_mac_multiStep_algo_pzz(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] = { 0x38,0x11,0x1B,0xD9,0xF1,0x4D,0x07,0x33,0x28,0xCB,0xB3,0x93,0x95,0xBC,0x69,0x98, };

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) + 1,
        (MAC_BLOCK_SIZE * 4),
        (MAC_BLOCK_SIZE * 4));
    return status;
}


sss_status_t test_mac_multiStep_algo_pzp(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] = { 0xD7,0xE0,0x43,0x16,0x1E,0x42,0x6B,0x81,0x97,0x4E,0xFC,0x0E,0x39,0xD5,0xAC,0xB8, };

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) + 1,
        (MAC_BLOCK_SIZE * 4),
        (MAC_BLOCK_SIZE * 4) + 1);
    return status;
}


sss_status_t test_mac_multiStep_algo_pzq(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] = { 0xE5,0xC8,0xF3,0x69,0xBB,0x35,0x95,0xE1,0x8B,0xCD,0x8F,0x93,0x26,0xD2,0x27,0x10, };

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) + 1,
        (MAC_BLOCK_SIZE * 4),
        (MAC_BLOCK_SIZE * 4) * 0);
    return status;
}


sss_status_t test_mac_multiStep_algo_ppm(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] = { 0xE9,0xCC,0x28,0x02,0x30,0x54,0xA0,0x0C,0x08,0x21,0x2E,0xB7,0x9F,0x71,0x94,0xEF, };

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) + 1,
        (MAC_BLOCK_SIZE * 4) + 1,
        (MAC_BLOCK_SIZE * 4) - 1);
    return status;
}


sss_status_t test_mac_multiStep_algo_ppz(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] = { 0xD0,0x8C,0x24,0x0E,0x7F,0x70,0x34,0x77,0x63,0xE7,0x76,0xF8,0xB2,0xAD,0xF4,0x87, };

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) + 1,
        (MAC_BLOCK_SIZE * 4) + 1,
        (MAC_BLOCK_SIZE * 4));
    return status;
}


sss_status_t test_mac_multiStep_algo_ppp(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] =         {0xE4,0xDF,0x2B,0x4B,0xB7,0x24,0xA5,0x7D,0xA5,0x31,0xB2,0x2D,0x82,0x71,0x66,0xFE,};
;

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) + 1,
        (MAC_BLOCK_SIZE * 4) + 1,
        (MAC_BLOCK_SIZE * 4) + 1);
    return status;
}


sss_status_t test_mac_multiStep_algo_ppq(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] =         {0x17,0xC6,0x24,0xD0,0x4C,0x3C,0x08,0x1C,0x26,0xEB,0x18,0x79,0xFC,0x8E,0x17,0x53,};
;

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) + 1,
        (MAC_BLOCK_SIZE * 4) + 1,
        (MAC_BLOCK_SIZE * 4) * 0);
    return status;
}


sss_status_t test_mac_multiStep_algo_pqm(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] =
    { 0x9E,0xC2,0x0A,0xE5,0x5C,0xC1,0x90,0xA2,0xE6,0x23,0xD4,0x1E,0xFB,0x5D,0x98,0x32, };

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) + 1,
        (MAC_BLOCK_SIZE * 4) * 0,
        (MAC_BLOCK_SIZE * 4) - 1);
    return status;
}


sss_status_t test_mac_multiStep_algo_pqz(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] = { 0xE7,0x6A,0xA2,0xC1,0xDE,0x97,0xDE,0x0F,0x09,0x61,0xD0,0xA2,0x40,0xBC,0x8E,0x6D, };;

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) + 1,
        (MAC_BLOCK_SIZE * 4) * 0,
        (MAC_BLOCK_SIZE * 4));
    return status;
}


sss_status_t test_mac_multiStep_algo_pqp(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] =
        {0x0F,0x45,0x6C,0x7F,0x52,0xFE,0xDB,0xF7,0xE8,0x45,0x0C,0x9D,0xA7,0x35,0x24,0x7A,};

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) + 1,
        (MAC_BLOCK_SIZE * 4) * 0,
        (MAC_BLOCK_SIZE * 4) + 1);
    return status;
}


sss_status_t test_mac_multiStep_algo_pqq(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] =
        {0x7F,0x49,0xE2,0x54,0xE5,0xA1,0x82,0xDD,0x5E,0xC3,0xC1,0x1B,0x48,0xD3,0x16,0x27,};

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) + 1,
        (MAC_BLOCK_SIZE * 4) * 0,
        (MAC_BLOCK_SIZE * 4) * 0);
    return status;
}


sss_status_t test_mac_multiStep_algo_qmm(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] =
        {0x5D,0x5C,0x78,0x11,0x8F,0x14,0x65,0xC3,0xC7,0x61,0xE7,0x3B,0x84,0xF6,0xCE,0xCE,};

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) * 0,
        (MAC_BLOCK_SIZE * 4) - 1,
        (MAC_BLOCK_SIZE * 4) - 1);
    return status;
}


sss_status_t test_mac_multiStep_algo_qmz(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] =
        {0x4A,0x71,0xA4,0xE5,0x8D,0xD0,0xA0,0x66,0xDE,0x31,0xB2,0xE7,0xAD,0xB8,0xD9,0xF6,};

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) * 0,
        (MAC_BLOCK_SIZE * 4) - 1,
        (MAC_BLOCK_SIZE * 4));
    return status;
}


sss_status_t test_mac_multiStep_algo_qmp(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] =
       {0x51,0x6A,0xBE,0xEB,0x00,0x86,0xDE,0xB6,0xAC,0x89,0x9A,0x9F,0x87,0xE9,0x62,0x86,};

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) * 0,
        (MAC_BLOCK_SIZE * 4) - 1,
        (MAC_BLOCK_SIZE * 4) + 1);
    return status;
}


sss_status_t test_mac_multiStep_algo_qmq(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] =
        {0x78,0x14,0x6B,0xA9,0x06,0xFC,0x66,0x36,0xDC,0x43,0xD0,0x97,0x2B,0xDF,0x1D,0xEF,};

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) * 0,
        (MAC_BLOCK_SIZE * 4) - 1,
        (MAC_BLOCK_SIZE * 4) * 0);
    return status;
}


sss_status_t test_mac_multiStep_algo_qzm(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] =
        {0x37,0xCA,0xAD,0xE1,0xE4,0x2A,0x93,0xC6,0xB6,0x84,0xE6,0xA4,0xF3,0x4D,0x56,0x9D,};

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) * 0,
        (MAC_BLOCK_SIZE * 4),
        (MAC_BLOCK_SIZE * 4) - 1);
    return status;
}


sss_status_t test_mac_multiStep_algo_qzz(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] =
        {0xB6,0x4F,0x1A,0x86,0xF8,0xFA,0x78,0x19,0xE0,0x7B,0xB3,0x22,0x27,0x9F,0xF5,0xED,};

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) * 0,
        (MAC_BLOCK_SIZE * 4),
        (MAC_BLOCK_SIZE * 4));
    return status;
}


sss_status_t test_mac_multiStep_algo_qzp(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] =
        {0xC0,0x33,0xDA,0xA7,0x1B,0xD6,0xA1,0x9B,0x2F,0x9E,0x42,0x2C,0x55,0x45,0xE3,0xE4,};

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) * 0,
        (MAC_BLOCK_SIZE * 4),
        (MAC_BLOCK_SIZE * 4) + 1);
    return status;
}


sss_status_t test_mac_multiStep_algo_qzq(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] =
        {0x33,0x18,0xE9,0x1D,0xDD,0x67,0xDF,0x78,0xAB,0xB2,0xE0,0x81,0xA0,0xAF,0xC2,0x78,};

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) * 0,
        (MAC_BLOCK_SIZE * 4),
        (MAC_BLOCK_SIZE * 4) * 0);
    return status;
}


sss_status_t test_mac_multiStep_algo_qpm(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] =
        {0x20,0x2C,0x59,0x8B,0x5F,0xFD,0xBB,0x3D,0x8B,0xC7,0x21,0x2F,0x2A,0x74,0xF3,0xC2,};

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) * 0,
        (MAC_BLOCK_SIZE * 4) + 1,
        (MAC_BLOCK_SIZE * 4) - 1);
    return status;
}


sss_status_t test_mac_multiStep_algo_qpz(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] =
        {0x84,0x2C,0xBC,0xD2,0x1A,0xEB,0xD3,0xF4,0xA6,0xCF,0x3D,0xD7,0xAF,0xDF,0xF7,0xB9,};

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) * 0,
        (MAC_BLOCK_SIZE * 4) + 1,
        (MAC_BLOCK_SIZE * 4));
    return status;
}


sss_status_t test_mac_multiStep_algo_qpp(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] =
        {0x1B,0x08,0xEE,0x62,0x89,0xDA,0x5E,0x57,0x87,0x20,0xE2,0x5D,0x85,0x8C,0x7E,0xB4,};

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) * 0,
        (MAC_BLOCK_SIZE * 4) + 1,
        (MAC_BLOCK_SIZE * 4) + 1);
    return status;
}


sss_status_t test_mac_multiStep_algo_qpq(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] =
        {0xCB,0xE6,0xF2,0x93,0x55,0x14,0xFA,0x5C,0x44,0x49,0xDB,0x55,0x82,0x43,0xFE,0x7E,};

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) * 0,
        (MAC_BLOCK_SIZE * 4) + 1,
        (MAC_BLOCK_SIZE * 4) * 0);
    return status;
}


sss_status_t test_mac_multiStep_algo_qqm(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] =
        {0x6E,0xD0,0x7C,0x27,0x21,0x48,0x25,0x41,0xC4,0xCD,0xEE,0x53,0x9B,0x3F,0xC9,0x95,};

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) * 0,
        (MAC_BLOCK_SIZE * 4) * 0,
        (MAC_BLOCK_SIZE * 4) - 1);
    return status;
}


sss_status_t test_mac_multiStep_algo_qqz(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] =
        {0x4D,0x4C,0x25,0x1E,0x6D,0x0D,0xC3,0x81,0x98,0x5B,0xEC,0xC7,0x10,0x5F,0xE7,0xD4,};

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) * 0,
        (MAC_BLOCK_SIZE * 4) * 0,
        (MAC_BLOCK_SIZE * 4));
    return status;
}


sss_status_t test_mac_multiStep_algo_qqp(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] =
        {0x6D,0x5D,0xF5,0x9F,0x0B,0xC1,0x67,0xBC,0xF3,0x70,0x95,0x9B,0x91,0x08,0x2B,0x64,};

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) * 0,
        (MAC_BLOCK_SIZE * 4) * 0,
        (MAC_BLOCK_SIZE * 4) + 1);
    return status;
}


sss_status_t test_mac_multiStep_algo_qqq(userCtx_t *pUserCtx) {
    sss_status_t status;
    const uint8_t expectedData[MAC_BLOCK_SIZE] =
        {0xB8,0xE0,0x0B,0x59,0xAC,0x33,0xAE,0x74,0xAF,0x09,0x30,0xC0,0x2A,0xFC,0xF3,0x11,};

    status = test_mac_multiStep_algo(pUserCtx, expectedData,
        MAC_BLOCK_SIZE,
        (MAC_BLOCK_SIZE * 4) * 0,
        (MAC_BLOCK_SIZE * 4) * 0,
        (MAC_BLOCK_SIZE * 4) * 0);
    return status;
}



static sss_status_t test_mac_multiStep_algo(userCtx_t *pUserCtx,
    const uint8_t expectedData[MAC_BLOCK_SIZE],
    const uint16_t srcData1Len,
    const uint16_t srcData2Len,
    const uint16_t srcData3Len,
    const uint16_t srcData4Len
    )
{
    sss_status_t status;
    uint8_t outdata[256] = { 0 };
    size_t outdatLen = sizeof(outdata);
    size_t count = 0;

    sss_algorithm_t algorithm = kAlgorithm_SSS_CMAC_AES;
    sss_mode_t mode = kMode_SSS_Mac;

    status = sss_host_key_object_allocate_handle(&pUserCtx->key,
        __LINE__,
        kSSS_KeyPart_Default,
        kSSS_CipherType_CMAC,
        16,
        kKeyObject_Mode_Transient);
    if (status != kStatus_SSS_Success)
    {
        LOG_E("Userkey_key_object_alloc_mac_multiStep Failed!!!");
        goto exit;
    }

    status = sss_host_key_store_set_key(&pUserCtx->ks,
        &pUserCtx->key,
        keystring,
        sizeof(keystring),
        sizeof(keystring) * 8,
        NULL,
        0);
    if (status != kStatus_SSS_Success)
    {
        LOG_E("Userkey_set_key_mac_multiStep Failed!!!");
        goto exit;
    }

    status = sss_host_mac_context_init(
        &pUserCtx->mac, &pUserCtx->session, &pUserCtx->key, algorithm, mode);
    if (status != kStatus_SSS_Success)
    {
        LOG_E("Userkey_mac_context_init_multiStep Failed!!!");
        goto exit;
    }

    status = sss_host_mac_init(&pUserCtx->mac);
    if (status != kStatus_SSS_Success)
    {
        LOG_E("Userkey_mac_init_multiStep Failed!!!");
        goto exit;
    }

    if (srcData1Len > 0) {
        status = sss_host_mac_update(&pUserCtx->mac, gSRCData1, srcData1Len);
        if (status != kStatus_SSS_Success)
        {
            LOG_E("Userkey_mac_update_multiStep step1 Failed!!!");
            goto exit;
        }
    }


    if (srcData2Len > 0) {
        status = sss_host_mac_update(&pUserCtx->mac, gSRCData2, srcData2Len);
        if (status != kStatus_SSS_Success)
        {
            LOG_E("Userkey_mac_update_multiStep step2 Failed!!!");
            goto exit;
        }
    }

    if (srcData3Len > 0) {
        status = sss_host_mac_update(&pUserCtx->mac, srcData3, srcData3Len);
        if (status != kStatus_SSS_Success)
        {
            LOG_E("Userkey_mac_update_multiStep step2 Failed!!!");
            goto exit;
        }
    }
    if (srcData4Len > 0) {
        status = sss_host_mac_update(&pUserCtx->mac, srcData4, srcData4Len);
        if (status != kStatus_SSS_Success)
        {
            LOG_E("Userkey_mac_update_multiStep step2 Failed!!!");
            goto exit;
        }
    }
    status = sss_host_mac_finish(&pUserCtx->mac, outdata, &outdatLen);
    if (status != kStatus_SSS_Success)
    {
        LOG_E("Userkey_mac_finish_multiStep Failed!!!");
        goto exit;
    }
    LOG_AU8_I(outdata, outdatLen);

    if (outdatLen != MAC_BLOCK_SIZE) {
        status = kStatus_SSS_Fail;
        goto exit;
    }

    for (count = 0;count < outdatLen;count++)
    {
        if (outdata[count] != expectedData[count])
        {
            LOG_E("Crypto results are wrong mac_multiStep !!!");
            LOG_MAU8_E("Expected", expectedData, MAC_BLOCK_SIZE);
            printf("\n        {");
            for (size_t i = 0; i < outdatLen; i++) {
                printf("0x%02X,", outdata[i]);
            }
            printf("};\n\n");
            //LOG_MAU8_E("Got", outdata, outdatLen);
            status = kStatus_SSS_Fail;
            break;
        }
    }

#if 0
   // sss_host_key_object_free(&pUserCtx->key);
    sss_host_mac_context_free(&pUserCtx->mac);
    status = sss_host_mac_context_init(
        &pUserCtx->mac, &pUserCtx->session, &pUserCtx->key, algorithm, mode);
    status = sss_host_mac_init(&pUserCtx->mac);
    status = sss_host_mac_update(&pUserCtx->mac, expectedData, 16);
    status = sss_host_mac_update(&pUserCtx->mac, srcData3, srcData3Len);
    sss_host_mac_finish(&pUserCtx->mac, outdata, &outdatLen);
#endif

exit:
    sss_host_key_object_free(&pUserCtx->key);
    sss_host_mac_context_free(&pUserCtx->mac);
    sss_host_key_store_context_free(&pUserCtx->ks);
    return status;
}
