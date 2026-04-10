/* Copyright 2019,2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "tst_sm_time.h"
#include <stdio.h>

static char* indent_table[] = { "",
"",
"    ",
"        ",
"            ",
"                ",
"                    ",
"                        ",
"                            ",
"                                ",
"                                    ",
"                                        ",
"                                            ",
"                                                ",
"                                                    ",
"                                                        ",
"                                                            ",
"                                                                ",
"                                                                    ",
"                                                                        ",
"                                                                            ",
"                                                                                ",
};

static int indent_level = 5;

#define TIMING_START(x) \
    printf("TIMING_START - %s" #x "\n", indent_table[indent_level++]); \
    axTimeMeasurement_t x;  \
    initMeasurement(& x);


#define TIMING_STOP(x)  \
    concludeMeasurement(& x); \
    printf( "TIMING_STOP  - %s" #x ": %d\n", indent_table[--indent_level], (unsigned int)getMeasurement(& x));
