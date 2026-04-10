/*
 * Copyright 2019-2021,2024 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */


#include <stdio.h>
#include <stdint.h>

#ifdef _WIN32
#include <direct.h>
#include <dirent_win32.h>
#else
#include <dirent.h>
#endif

 // Define this function here as it has influence on the
 // logging in the agent itself if included
#define IOT_AGENT_TEST      1

#include <nxp_iot_agent_session.h>
#include <nxp_iot_agent_macros.h>
#include <nxp_iot_agent_macros_sss.h>
#include <iot_agent_claimcode_inject.h>

static ex_sss_boot_ctx_t gex_sss_boot_ctx;

#define DEFAULT_USER_ID     		0x00000000U
#define EDGELOCK2GO_USER_ID_DEMO 	0xF0000021U
#define EDGELOCK2GO_USER_ID      	0xF0000020U

static void print_usage()
{

    printf("Inject claim code from a given file into Secure element\n");
    printf(" Usage:\n");
    printf(" To inject new claim code: el2go_claimcode_inject filename\n");
    printf(" To delete existing claim code:el2go_claimcode_inject --delete\n");
    printf("\n");
}

static size_t validate_claimcode(char * src, char* dest, size_t len)
{
    size_t srcPtr = 0U;
    size_t destPtr = 0U;

    while ((srcPtr < len) && (destPtr < len) && (src[srcPtr] != '\0'))
    {
        if (!(src[srcPtr] == ' ' || src[srcPtr] == '\r' || src[srcPtr] == '\n')) {
            dest[destPtr] = src[srcPtr];
            destPtr++;
        }
        srcPtr++;
    }
    if (destPtr < len) {
        dest[destPtr] = '\0';
    }
    return destPtr;
}

int main(int argc, const char *argv[])
{
    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
    sss_status_t sss_status;
    sss_object_t obj;
    char file_name[255] = { 0 };
    FILE *fp = NULL;
    char *claimcode_file = NULL;
    char *claimcode_valid = NULL;
    size_t claimcode_valid_len = 0U;
    long claimcode_len = 0;

    if (argc < 2 || argc > 3)
    {
        printf(" Wrong number of arguments:\n");
        print_usage();
        return 1;
    }

    if (argc == 2)
    {
        agent_status = iot_agent_session_init(0U, NULL, &gex_sss_boot_ctx);
    }
    else
    {
        agent_status = iot_agent_session_init(argc, argv, &gex_sss_boot_ctx);
    }

    AGENT_SUCCESS_OR_EXIT();

    sss_status = sss_key_object_init(&obj, &gex_sss_boot_ctx.ks);
    SSS_SUCCESS_OR_EXIT_MSG("sss_key_object_init failed with 0x%04x", sss_status);

    //delete claimcode if requested
    if (strcmp(argv[1], "--delete") == 0)
    {
        obj.keyId = CLAIMCODE_OBJ_ID;
        sss_status = sss_key_store_erase_key(&gex_sss_boot_ctx.ks, &obj);
        SSS_SUCCESS_OR_EXIT_MSG("sss_key_store_erase_key failed with 0x%04x", sss_status);
        printf("Deleting claim code successful!\n");
        return agent_status;
    }

    //Read claim code from file
    strncpy(file_name, argv[1], sizeof(file_name) - 1U);
    fp = fopen(file_name, "rb");
    ASSERT_OR_EXIT_MSG(fp != NULL, "Can not open the file [%s]", file_name);

    ASSERT_OR_EXIT_MSG(fseek(fp, 0U, SEEK_END) == 0, "Error in fseek function");
    claimcode_len = ftell(fp);
    ASSERT_OR_EXIT_MSG(claimcode_len > 0, "Empty file read");
    ASSERT_OR_EXIT_MSG(fseek(fp, 0U, SEEK_SET) == 0, "Error in fseek function");
    claimcode_file = malloc((size_t)claimcode_len + 1U);
    ASSERT_OR_EXIT_MSG(claimcode_file != NULL, "malloc failed");
    ASSERT_OR_EXIT_MSG(fread(claimcode_file, 1U, (size_t)claimcode_len, fp) == (size_t)claimcode_len, "File read failed");
    claimcode_file[claimcode_len] = '\0';

    claimcode_valid = malloc((size_t)claimcode_len + 1U);
    ASSERT_OR_EXIT_MSG(claimcode_valid != NULL, "malloc failed");
    claimcode_valid_len = validate_claimcode(claimcode_file, claimcode_valid, (size_t)claimcode_len + 1U);
    //printf("Claim Code from file:[%s]\n", claimcode_file);
    //printf("Injecting ClaimCode:[%s]\n", claimcode_valid);

    agent_status = iot_agent_claimcode_inject(&gex_sss_boot_ctx, claimcode_valid, claimcode_valid_len);
    AGENT_SUCCESS_OR_EXIT_MSG("Injecting claim code failed!\n");

exit:
    if (fp != NULL)
    {
        if (fclose(fp) != 0)
        {
            IOT_AGENT_ERROR("Error in closing the file");
        }
    }
    free(claimcode_file);
    free(claimcode_valid);

    return agent_status;
}
