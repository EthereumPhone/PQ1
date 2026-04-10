#ifndef _OTA_PAL_TEST_H_
#define _OTA_PAL_TEST_H_

#include <stdint.h>

typedef struct OtaPalTestParam
{
    uint32_t pageSize;
} OtaPalTestParam_t;

void SetupOtaPalTestParam( OtaPalTestParam_t * pTestParam );

int RunOtaPalTest( void );

#endif /* _OTA_PAL_TEST_H_ */
